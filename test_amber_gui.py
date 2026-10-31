"""Small offline smoke tests for the native amber dashboard; no live network."""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import desktop


class AmberAssetTests(unittest.TestCase):
    def test_shipped_hud_and_amber_palette(self):
        self.assertTrue((desktop.ROOT / 'assets' / 'omega_hud_core.png').is_file())
        self.assertEqual(desktop.PINK, '#ff991e')
        self.assertNotEqual(desktop.DANGER, desktop.PINK)
        self.assertEqual(len(desktop.STAGES), 5)


@unittest.skipUnless(os.environ.get('DISPLAY') or sys.platform == 'win32',
                     'Tkinter requires a display')
class AmberWindowTests(unittest.TestCase):
    def test_dashboard_starts_idle_and_wires_real_hunt(self):
        import tkinter as tk
        root = tk.Tk()
        try:
            # Test the layout independently of private prior-hunt telemetry.
            with patch('desktop_status.read_status', return_value=None), \
                 patch('desktop_status.snapshot_summary', return_value=None):
                app = desktop.Dashboard(root)
                root.update()
            self.assertIn('STANDBY', app.hub_title.get())
            self.assertTrue(app.hub_canvas.winfo_width() > 50)
            self.assertEqual(app.quick_button['state'], 'normal')
            with patch('desktop.open_terminal') as terminal:
                terminal.return_value.poll.return_value = None
                app.quick_button.invoke()
            self.assertTrue(terminal.called)
            argv = terminal.call_args.args[0]
            self.assertIn('terminal_runner.py', argv[1])
            self.assertIn('--recheck', argv)
            self.assertTrue(app.live)
            self.assertIn('STARTING', app.hub_title.get())
            self.assertEqual(app.quick_button['state'], 'disabled')
            app.live = False
        finally:
            root.destroy()

if __name__ == '__main__':
    unittest.main()
