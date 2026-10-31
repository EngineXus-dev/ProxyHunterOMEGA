"""Regressions for claims disproved by the October 31 cache audit; no network."""
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from profiler import classify_type
from threat_intelligence import enrich_proxy_intel, evaluate_device_heuristics, check_asn_datacenter_mismatch
from network_classification import evidence_tag, category, distinct_exit_count
from desktop_status import snapshot_summary
from pipeline import export_results
from state import State
from recent_results import export_latest


class ClassificationTruthTests(unittest.TestCase):
    def test_brand_is_not_residential_proof(self):
        self.assertEqual(classify_type('Orange CAM INTERNET', 'Orange Cameroun SA', False), 'isp_unverified')
        self.assertNotEqual(classify_type('Orange CAM INTERNET', '', False), 'residential')

    def test_wireless_name_is_not_cellular_device_proof(self):
        self.assertEqual(classify_type('Advanced Wireless Network Company Limited', '', False), 'unknown')
        self.assertEqual(classify_type('T-Mobile USA', '', False), 'carrier_unverified')

    def test_no_fabricated_device_counts(self):
        for latency in (0.3, 1.5, 8):
            result = evaluate_device_heuristics('8.8.8.8', latency, 'unknown', 1080)
            self.assertIsNone(result['device_count_est'])

    def test_isp_classification_cannot_emit_clean_residential(self):
        proxy={'proxy':'8.8.8.8:8080', 'proto':'http', 'latency':.5,
               'exit_ip':'8.8.4.4', 'type':'isp_unverified', 'score':60}
        geo={'isp':'Orange CAM INTERNET', 'org':'Orange Cameroun SA', 'hosting':False, 'as':'AS36912 Orange Cameroun SA'}
        result=enrich_proxy_intel(proxy,geo)
        self.assertEqual(result['threat_tag'], 'ISP_NETWORK_UNVERIFIED')
        self.assertFalse(result['access_type_verified'])
        self.assertFalse(result['is_clean_residential'])
        self.assertIsNone(result['device_count_est'])

    def test_legacy_mobile_keyword_relabels_as_isp_not_mobile(self):
        self.assertEqual(evidence_tag({'threat_tag':'CLEAN_MOBILE'}), 'ISP_NETWORK_UNVERIFIED')
        self.assertEqual(category({'threat_tag':'CLEAN_RESIDENTIAL'}), 'isp')

    def test_same_exit_across_ports_counts_one(self):
        rows=[{'proxy':f'102.244.78.61:{port}', 'exit_ip':'102.244.78.57'} for port in (8080,8082,8084,8086)]
        self.assertEqual(distinct_exit_count(rows),1)

    def test_old_snapshot_never_shows_proven_residential(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'latest_results.json'
            path.write_text(json.dumps({'validated':[{'proxy':'8.8.8.8:80', 'exit_ip':'8.8.4.4','threat_tag':'CLEAN_RESIDENTIAL'},
                                                    {'proxy':'1.1.1.1:80', 'exit_ip':'1.0.0.1','threat_tag':'CLEAN_MOBILE'}],
                                        'result':'completed'}))
            summary=snapshot_summary(path)
            self.assertEqual(summary['counters']['isp'],2)
            self.assertEqual(summary['counters']['carrier'],0)
            self.assertEqual(summary['distinct_exits'],2)
            self.assertNotIn('proxy',summary)

    def test_legacy_clean_files_cleared_but_candidates_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            state=State()
            state.profiled=[{'proxy':'8.8.8.8:8080','proto':'http','exit_ip':'8.8.4.4',
                             'threat_tag':'CLEAN_RESIDENTIAL','confirmed':True}]
            export_results(state,d)
            self.assertEqual((Path(d)/'clean_residential_verified.txt').read_text(),'')
            self.assertEqual((Path(d)/'potential_residential_live.txt').read_text(),'')
            self.assertEqual((Path(d)/'isp_network_candidates_live.txt').read_text(),'8.8.8.8:8080\n')

    def test_export_legacy_json_and_csv_relabels_without_modifying_original(self):
        import os
        with tempfile.TemporaryDirectory() as d:
            old=Path(d)/'latest_results.json'
            doc={'result':'completed','validated':[{'proxy':'8.8.8.8:80','proto':'http','exit_ip':'8.8.4.4',
                     'threat_tag':'CLEAN_RESIDENTIAL','confirmed':True}]}
            old.write_text(json.dumps(doc))
            with patch.dict(os.environ, {'PROXYHUNTER_DATA_DIR':d}):
                export_latest(Path(d)/'out.json')
                export_latest(Path(d)/'out.csv')
            exported=json.loads((Path(d)/'out.json').read_text())
            self.assertEqual(exported['validated'][0]['threat_tag'],'ISP_NETWORK_UNVERIFIED')
            self.assertFalse(exported['validated'][0]['access_type_verified'])
            self.assertEqual(exported['residential_access_proven'],0)
            self.assertIn('ISP_NETWORK_UNVERIFIED',(Path(d)/'out.csv').read_text())
            self.assertIn('CLEAN_RESIDENTIAL',old.read_text())

    def test_asn_network_label_not_authenticity_proof(self):
        result=check_asn_datacenter_mismatch(36912,'Orange Cameroun SA','Orange CAM INTERNET','',False)
        self.assertEqual(result['tag'],'ACCESS_TYPE_UNKNOWN')
        self.assertNotIn('authentic', result['reason'].lower())


if __name__ == '__main__':
    unittest.main()
