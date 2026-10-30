// Native Windows client. Builds with the .NET Framework compiler shipped with Windows.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace RouteBar.Windows
{
    public sealed class Vpn { public string wireguard_config { get; set; } }
    public sealed class Dns
    {
        public string server { get; set; }
        public string via { get; set; }
        public string strategy { get; set; }
        public Dns() { server = "1.1.1.1"; via = "direct"; strategy = "auto"; }
    }
    public sealed class Selectors
    {
        public string[] apps { get; set; }
        public string[] process_names { get; set; }
        public string[] domains { get; set; }
        public string[] domain_suffixes { get; set; }
        public string[] ip_cidrs { get; set; }
        public Selectors() { apps = process_names = domains = domain_suffixes = ip_cidrs = new string[0]; }
        public override string ToString() { return string.Join("; ", apps.Concat(process_names).Concat(domains).Concat(domain_suffixes.Select(s => "*." + s)).Concat(ip_cidrs)); }
    }
    public sealed class Rule
    {
        public string name { get; set; }
        public Selectors match { get; set; }
        public string via { get; set; }
        public Rule() { name = "New rule"; match = new Selectors(); via = "direct"; }
    }
    public sealed class Routing
    {
        public string @default { get; set; }
        public List<Rule> rules { get; set; }
        public Routing() { @default = "direct"; rules = new List<Rule>(); }
    }
    public sealed class Document
    {
        public int version { get; set; }
        public Dictionary<string, Vpn> vpns { get; set; }
        public Dns dns { get; set; }
        public Routing routing { get; set; }
        public Document() { version = 1; vpns = new Dictionary<string, Vpn>(); dns = new Dns(); routing = new Routing(); }
    }
    internal static class Store
    {
        internal static readonly string Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RouteBarWindows");
        internal static readonly string ConfigPath = Path.Combine(Root, "config.json");
        internal static JavaScriptSerializer Json() { return new JavaScriptSerializer { MaxJsonLength = 1024 * 1024, RecursionLimit = 100 }; }
        internal static DirectorySecurity Security()
        {
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            foreach (var sid in new[] { WindowsIdentity.GetCurrent().User, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) })
                acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            return acl;
        }
        internal static void PrivateDirectory(string path)
        {
            if (Directory.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("RouteBar storage must not be a symbolic link or junction.");
            Directory.CreateDirectory(path, Security());
            Directory.SetAccessControl(path, Security());
        }
        internal static void Write(string path, string value)
        {
            string temp = Path.Combine(Path.GetDirectoryName(path), Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    var bytes = new UTF8Encoding(false).GetBytes(value);
                    stream.Write(bytes, 0, bytes.Length); stream.Flush(true);
                }
                if (File.Exists(path)) File.Replace(temp, path, null); else File.Move(temp, path);
            }
            finally { if (File.Exists(temp)) File.Delete(temp); }
        }
        internal static void Save(Document doc) { PrivateDirectory(Root); Write(ConfigPath, Json().Serialize(doc)); }
        internal static Document Clone(Document doc) { return Json().Deserialize<Document>(Json().Serialize(doc)); }
    }
    internal static class Backend
    {
        internal static readonly string Controller = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "routebar-v2.exe");
        internal static string Quote(string value)
        {
            // CommandLineToArgvW quoting, including paths ending with backslashes.
            var b = new StringBuilder("\""); int slashes = 0;
            foreach (char c in value)
            {
                if (c == '\\') { slashes++; continue; }
                b.Append('\\', c == '"' ? slashes * 2 + 1 : slashes); slashes = 0; b.Append(c);
            }
            return b.Append('\\', slashes * 2).Append('"').ToString();
        }
        internal static ProcessStartInfo StartInfo(params string[] args)
        {
            return new ProcessStartInfo(Controller, string.Join(" ", args.Select(Quote))) {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true,
                RedirectStandardError = true, RedirectStandardInput = true,
                StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
                WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory
            };
        }
        internal static string Call(params string[] args)
        {
            using (var process = new Process { StartInfo = StartInfo(args) })
            {
                var output = new StringBuilder(); var error = new StringBuilder();
                process.OutputDataReceived += (s, e) => { if (e.Data != null) lock (output) { if (output.Length < 1024 * 1024) output.AppendLine(e.Data); } };
                process.ErrorDataReceived += (s, e) => { if (e.Data != null) lock (error) { if (error.Length < 16384) error.AppendLine(e.Data); } };
                process.Start(); process.StandardInput.Close(); process.BeginOutputReadLine(); process.BeginErrorReadLine();
                if (!process.WaitForExit(30000)) { process.Kill(); process.WaitForExit(); throw new IOException("Controller timed out."); }
                process.WaitForExit();
                if (process.ExitCode != 0) throw new IOException(error.ToString().Trim());
                if (output.Length >= 1024 * 1024) throw new IOException("Controller output exceeds 1 MiB.");
                return output.ToString();
            }
        }
        internal static Document Load(string file) { return Store.Json().Deserialize<Document>(Call("config-inspect", "-c", file)); }
        internal static bool IsAdmin { get { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); } }
    }
    // A snapshot includes profiles, so rollback is independent of edits to source files.
    internal sealed class Connection : IDisposable
    {
        internal readonly string DirectoryPath;
        internal readonly string ConfigPath;
        private Process process;
        internal bool IsRunning { get { return process != null && !process.HasExited; } }
        internal Connection(Document document)
        {
            DirectoryPath = Path.Combine(Store.Root, "session-" + Guid.NewGuid().ToString("N"));
            ConfigPath = Path.Combine(DirectoryPath, "config.json");
            Store.PrivateDirectory(DirectoryPath);
            try
            {
                var copy = Store.Clone(document); int index = 0;
                foreach (var vpn in copy.vpns.Values)
                {
                    string target = Path.Combine(DirectoryPath, "profile-" + index++ + ".conf");
                    var info = new FileInfo(vpn.wireguard_config);
                    if (info.Length > 128 * 1024) throw new IOException("WireGuard profile exceeds 128 KiB.");
                    Store.Write(target, File.ReadAllText(vpn.wireguard_config)); vpn.wireguard_config = target;
                }
                Store.Write(ConfigPath, Store.Json().Serialize(copy));
                Backend.Call("validate", "-c", ConfigPath);
            }
            catch { Directory.Delete(DirectoryPath, true); throw; }
        }
        internal void Start(Action<string> log)
        {
            var ready = new TaskCompletionSource<bool>();
            process = new Process { StartInfo = Backend.StartInfo("run", "-c", ConfigPath), EnableRaisingEvents = true };
            // Give the controller a hidden console for graceful CTRL_BREAK shutdown.
            process.StartInfo.CreateNoWindow = false; process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            process.OutputDataReceived += (s, e) => {
                if (e.Data == null) return;
                try
                {
                    var data = Store.Json().Deserialize<Dictionary<string, object>>(e.Data);
                    object kind; if (data.TryGetValue("event", out kind) && (string)kind == "running") ready.TrySetResult(true);
                    object message; if (data.TryGetValue("message", out message)) log(Convert.ToString(message));
                }
                catch { log("Controller emitted an unreadable status message."); }
            };
            process.ErrorDataReceived += (s, e) => { if (e.Data != null) log(e.Data); };
            process.Exited += (s, e) => ready.TrySetResult(false);
            try
            {
                process.Start(); process.BeginOutputReadLine(); process.BeginErrorReadLine();
                if (!ready.Task.Wait(30000) || !ready.Task.Result || !IsRunning) throw new IOException("VPN engine did not start. See Logs for details.");
            }
            catch { Stop(); throw; }
        }
        internal void Stop()
        {
            if (process == null) return;
            try
            {
                if (!process.HasExited)
                {
                    try { process.StandardInput.WriteLine("stop"); process.StandardInput.Flush(); process.StandardInput.Close(); } catch (IOException) { }
                    if (!process.WaitForExit(8000)) { process.Kill(); process.WaitForExit(5000); }
                }
                process.WaitForExit();
            }
            finally { process.Dispose(); process = null; }
        }
        public void Dispose() { Stop(); if (Directory.Exists(DirectoryPath)) Directory.Delete(DirectoryPath, true); }
    }

    internal sealed class RuleDialog : Form
    {
        private readonly TextBox name = new TextBox(), apps = new TextBox(), processes = new TextBox(), domains = new TextBox(), suffixes = new TextBox(), cidrs = new TextBox();
        private readonly ComboBox via = new ComboBox();
        internal Rule Result;
        internal RuleDialog(Rule rule, IEnumerable<string> exits)
        {
            Text = "Routing rule"; Size = new Size(620, 480); MinimumSize = Size; StartPosition = FormStartPosition.CenterParent;
            Font = new Font("Segoe UI", 10); BackColor = Color.White;
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(20), ColumnCount = 2, RowCount = 9 };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 160)); layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); Controls.Add(layout);
            Add(layout, "Rule name", name); Add(layout, "Applications (.exe)", apps); Add(layout, "Process names", processes);
            Add(layout, "Exact domains", domains); Add(layout, "Domain suffixes", suffixes); Add(layout, "IP ranges (CIDR)", cidrs); Add(layout, "Route through", via);
            name.Text = rule.name; apps.Text = string.Join("; ", rule.match.apps); processes.Text = string.Join("; ", rule.match.process_names);
            domains.Text = string.Join("; ", rule.match.domains); suffixes.Text = string.Join("; ", rule.match.domain_suffixes); cidrs.Text = string.Join("; ", rule.match.ip_cidrs);
            via.DropDownStyle = ComboBoxStyle.DropDownList; via.Items.AddRange(exits.Cast<object>().ToArray()); via.SelectedItem = rule.via;
            if (via.SelectedIndex < 0) via.SelectedIndex = 0;
            var hint = new Label { Text = "Separate values with semicolons. App/process matches AND destination matches. First matching rule wins.", AutoSize = true, MaximumSize = new Size(540, 60) };
            layout.Controls.Add(hint, 0, 7); layout.SetColumnSpan(hint, 2);
            var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true };
            var browse = new Button { Text = "Browse app...", AutoSize = true };
            browse.Click += (s, e) => { using (var dialog = new OpenFileDialog { Filter = "Applications|*.exe", CheckFileExists = true }) if (dialog.ShowDialog(this) == DialogResult.OK) apps.Text = apps.Text.Trim().Length == 0 ? dialog.FileName : apps.Text + "; " + dialog.FileName; };
            var save = new Button { Text = "Save rule", AutoSize = true }; var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
            save.Click += (s, e) => {
                Result = new Rule { name = name.Text.Trim(), via = (string)via.SelectedItem, match = new Selectors {
                    apps = Split(apps.Text), process_names = Split(processes.Text), domains = Split(domains.Text), domain_suffixes = Split(suffixes.Text), ip_cidrs = Split(cidrs.Text) } };
                DialogResult = DialogResult.OK; Close();
            };
            buttons.Controls.AddRange(new Control[] { browse, save, cancel }); layout.Controls.Add(buttons, 0, 8); layout.SetColumnSpan(buttons, 2); AcceptButton = save; CancelButton = cancel;
        }
        private static void Add(TableLayoutPanel layout, string label, Control control)
        {
            int row = layout.Controls.Count / 2; layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            layout.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left }, 0, row); control.Dock = DockStyle.Fill; layout.Controls.Add(control, 1, row);
        }
        private static string[] Split(string text) { return text.Split(';').Select(s => s.Trim()).Where(s => s.Length > 0).ToArray(); }
    }
    internal sealed class MainForm : Form
    {
        private Document document = new Document();
        private Connection active;
        private bool busy, quitting;
        private readonly Label status = new Label();
        private readonly ListView rules = new ListView(), vpns = new ListView();
        private readonly TextBox logs = new TextBox(), dnsServer = new TextBox();
        private readonly ComboBox dnsVia = new ComboBox(), strategy = new ComboBox(), fallback = new ComboBox();
        private readonly FlowLayoutPanel toolbar = new FlowLayoutPanel();
        private readonly TabControl tabs = new TabControl();
        private readonly NotifyIcon tray = new NotifyIcon();
        private readonly Timer timer = new Timer { Interval = 1000 };
        private Button connect;
        internal MainForm()
        {
            Text = "RouteBar for Windows"; ClientSize = new Size(1080, 720); MinimumSize = new Size(900, 620);
            StartPosition = FormStartPosition.CenterScreen; Font = new Font("Segoe UI", 10); BackColor = Color.FromArgb(245, 247, 251);
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(24), RowCount = 5, ColumnCount = 1 };
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 68)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 48)); layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 46)); Controls.Add(layout);
            layout.Controls.Add(new Label { Text = "RouteBar  /  Windows", Font = new Font("Segoe UI", 25, FontStyle.Bold), ForeColor = Color.FromArgb(24, 43, 76), Dock = DockStyle.Fill }, 0, 0);
            status.Text = "Disconnected • Unmatched traffic goes direct"; status.Dock = DockStyle.Fill; layout.Controls.Add(status, 0, 1);
            toolbar.Dock = DockStyle.Fill; layout.Controls.Add(toolbar, 0, 2);
            connect = Button(toolbar, "Connect", async () => await Connect());
            Button(toolbar, "Disconnect", async () => await Work(() => { if (active != null) { active.Dispose(); active = null; } }, "Disconnected"));
            Button(toolbar, "Validate", async () => await ValidateConfiguration());
            Button(toolbar, "Import config...", async () => await ImportConfig());
            Button(toolbar, "Export config...", Export);
            tabs.Dock = DockStyle.Fill; layout.Controls.Add(tabs, 0, 3);
            var rulesPage = Page("Routing rules"); var rulesLayout = Panel(rulesPage);
            var ruleButtons = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 44 };
            Button(ruleButtons, "Add rule", async () => await EditRule(false)); Button(ruleButtons, "Edit", async () => await EditRule(true));
            Button(ruleButtons, "Remove", async () => await ChangeRules("remove")); Button(ruleButtons, "Move up", async () => await ChangeRules("up")); Button(ruleButtons, "Move down", async () => await ChangeRules("down"));
            SetupList(rules, new[] { "Priority", "Name", "Match", "Exit" }, new[] { 70, 180, 520, 140 });
            rulesLayout.Controls.Add(rules); rulesLayout.Controls.Add(ruleButtons);
            var vpnPage = Page("VPN exits"); var vpnLayout = Panel(vpnPage);
            var vpnButtons = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 44 };
            Button(vpnButtons, "Import WireGuard .conf...", async () => await ImportVpn()); Button(vpnButtons, "Remove exit", async () => await RemoveVpn());
            SetupList(vpns, new[] { "Exit name", "Profile location" }, new[] { 180, 730 }); vpnLayout.Controls.Add(vpns); vpnLayout.Controls.Add(vpnButtons);
            var dnsPage = Page("DNS & default route");
            var dnsLayout = new TableLayoutPanel { Dock = DockStyle.Top, Padding = new Padding(20), ColumnCount = 2, RowCount = 6, Height = 320 };
            dnsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 220)); dnsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); dnsPage.Controls.Add(dnsLayout);
            var labels = new[] { "DNS server (IP address)", "DNS exit", "Address family", "Unmatched traffic" };
            var fields = new Control[] { dnsServer, dnsVia, strategy, fallback };
            for (int i = 0; i < fields.Length; i++) { dnsLayout.Controls.Add(new Label { Text = labels[i], AutoSize = true }, 0, i); fields[i].Dock = DockStyle.Fill; dnsLayout.Controls.Add(fields[i], 1, i); dnsLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 44)); }
            foreach (var combo in new[] { dnsVia, strategy, fallback }) combo.DropDownStyle = ComboBoxStyle.DropDownList;
            strategy.Items.AddRange(new object[] { "auto", "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only" });
            var dnsButtons = new FlowLayoutPanel { Dock = DockStyle.Fill }; Button(dnsButtons, "Save DNS & default", async () => await SaveDns()); dnsLayout.Controls.Add(dnsButtons, 1, 4);
            var dnsHint = new Label { Text = "DNS uses a separate global policy. Selecting an app's VPN does not automatically route DNS through it.", Dock = DockStyle.Fill, AutoSize = true }; dnsLayout.Controls.Add(dnsHint, 0, 5); dnsLayout.SetColumnSpan(dnsHint, 2);
            var logPage = Page("Logs"); logs.Multiline = true; logs.ReadOnly = true; logs.ScrollBars = ScrollBars.Both; logs.WordWrap = false; logs.Font = new Font("Consolas", 9); logs.Dock = DockStyle.Fill; logPage.Controls.Add(logs);
            layout.Controls.Add(new Label { Text = "First match wins. Apply changes restarts active connections. No kill switch. Exit stops the VPN; minimize keeps it running.", Dock = DockStyle.Fill, Padding = new Padding(0, 12, 0, 0) }, 0, 4);
            tray.Icon = SystemIcons.Application; tray.Text = "RouteBar for Windows"; tray.Visible = true;
            var menu = new ContextMenuStrip(); menu.Items.Add("Show RouteBar", null, (s, e) => ShowWindow()); menu.Items.Add("Exit and disconnect", null, (s, e) => Close()); tray.ContextMenuStrip = menu; tray.DoubleClick += (s, e) => ShowWindow();
            Resize += (s, e) => { if (WindowState == FormWindowState.Minimized) Hide(); };
            FormClosing += OnClosing;
            Shown += async (s, e) => await Work(() => { Store.PrivateDirectory(Store.Root); if (File.Exists(Store.ConfigPath)) document = Backend.Load(Store.ConfigPath); }, "Ready");
            timer.Tick += (s, e) => {
                if (!busy && active != null && !active.IsRunning) { var ended = active; active = null; try { ended.Dispose(); } catch (Exception ex) { Log(ex.Message); } status.Text = "Disconnected • Engine stopped unexpectedly; see Logs"; connect.Text = "Connect"; }
            }; timer.Start(); RefreshDocument();
        }
        private static Button Button(Control parent, string text, Action action)
        {
            var button = new Button { Text = text, AutoSize = true, Height = 32, Padding = new Padding(7, 2, 7, 2), FlatStyle = FlatStyle.System };
            button.Click += (s, e) => action(); parent.Controls.Add(button); return button;
        }
        private TabPage Page(string title) { var page = new TabPage(title) { BackColor = Color.White, Padding = new Padding(8) }; tabs.TabPages.Add(page); return page; }
        private static Panel Panel(Control parent) { var panel = new Panel { Dock = DockStyle.Fill }; parent.Controls.Add(panel); return panel; }
        private static void SetupList(ListView list, string[] labels, int[] widths)
        {
            list.Dock = DockStyle.Fill; list.View = View.Details; list.FullRowSelect = true; list.HideSelection = false; list.MultiSelect = false;
            for (int i = 0; i < labels.Length; i++) list.Columns.Add(labels[i], widths[i]);
        }
        private void ShowWindow() { Show(); WindowState = FormWindowState.Normal; Activate(); }
        private IEnumerable<string> Exits { get { return new[] { "direct" }.Concat(document.vpns.Keys); } }
        private void RefreshDocument()
        {
            rules.Items.Clear(); for (int i = 0; i < document.routing.rules.Count; i++) { var r = document.routing.rules[i]; rules.Items.Add(new ListViewItem(new[] { (i + 1).ToString(), r.name, r.match.ToString(), r.via })); }
            vpns.Items.Clear(); foreach (var pair in document.vpns) vpns.Items.Add(new ListViewItem(new[] { pair.Key, pair.Value.wireguard_config }));
            foreach (var combo in new[] { dnsVia, fallback }) { combo.Items.Clear(); combo.Items.AddRange(Exits.Cast<object>().ToArray()); }
            dnsServer.Text = document.dns.server; dnsVia.SelectedItem = document.dns.via; strategy.SelectedItem = document.dns.strategy; fallback.SelectedItem = document.routing.@default;
            connect.Text = active == null ? "Connect" : "Apply changes";
        }
        private void Log(string message)
        {
            if (IsDisposed || Disposing) return;
            if (InvokeRequired) { try { BeginInvoke(new Action<string>(Log), message); } catch (InvalidOperationException) { } return; }
            if (logs.TextLength > 64000) logs.Text = logs.Text.Substring(logs.TextLength - 32000);
            logs.AppendText(DateTime.Now.ToString("HH:mm:ss") + "  " + message + Environment.NewLine);
        }
        private async Task Work(Action action, string success)
        {
            if (busy) return;
            busy = true; toolbar.Enabled = false; tabs.Enabled = false; status.Text = "Working...";
            try { await Task.Run(action); status.Text = active != null && active.IsRunning ? "Running • Process status only; VPN egress is not verified" : success; RefreshDocument(); }
            catch (Exception ex) { Log(ex.Message); status.Text = active != null && active.IsRunning ? "Previous connection restored • Requested change failed" : "Action failed • See Logs"; MessageBox.Show(this, ex.Message, "RouteBar", MessageBoxButtons.OK, MessageBoxIcon.Error); }
            finally { toolbar.Enabled = true; tabs.Enabled = true; busy = false; }
        }
        private async Task SaveCandidate(Document candidate)
        {
            await Work(() => {
                string path = Path.Combine(Store.Root, "candidate-" + Guid.NewGuid().ToString("N") + ".json");
                try { Store.Write(path, Store.Json().Serialize(candidate)); var normalized = Backend.Load(path); Store.Save(normalized); document = normalized; }
                finally { if (File.Exists(path)) File.Delete(path); }
            }, "Saved • Connect or Apply changes to use these rules");
        }
        private async Task EditRule(bool edit)
        {
            int index = rules.SelectedIndices.Count > 0 ? rules.SelectedIndices[0] : -1;
            if (edit && index < 0) return;
            using (var dialog = new RuleDialog(edit ? document.routing.rules[index] : new Rule(), Exits))
                if (dialog.ShowDialog(this) == DialogResult.OK) { var candidate = Store.Clone(document); if (edit) candidate.routing.rules[index] = dialog.Result; else candidate.routing.rules.Add(dialog.Result); await SaveCandidate(candidate); }
        }
        private async Task ChangeRules(string change)
        {
            if (rules.SelectedIndices.Count == 0) return;
            int index = rules.SelectedIndices[0]; var candidate = Store.Clone(document);
            if (change == "remove") candidate.routing.rules.RemoveAt(index);
            else { int next = index + (change == "up" ? -1 : 1); if (next < 0 || next >= candidate.routing.rules.Count) return; var rule = candidate.routing.rules[index]; candidate.routing.rules.RemoveAt(index); candidate.routing.rules.Insert(next, rule); }
            await SaveCandidate(candidate);
        }
        private async Task SaveDns()
        {
            var candidate = Store.Clone(document); candidate.dns.server = dnsServer.Text.Trim(); candidate.dns.via = (string)dnsVia.SelectedItem;
            candidate.dns.strategy = (string)strategy.SelectedItem; candidate.routing.@default = (string)fallback.SelectedItem; await SaveCandidate(candidate);
        }
        private async Task ImportVpn()
        {
            using (var dialog = new OpenFileDialog { Filter = "WireGuard profiles|*.conf", CheckFileExists = true })
            {
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                string file = dialog.FileName;
                await Work(() => {
                    var candidate = Store.Clone(document); string tag = "vpn"; int n = 1; while (candidate.vpns.ContainsKey(tag)) tag = "vpn" + ++n;
                    string target = Path.Combine(Store.Root, "profile-" + Guid.NewGuid().ToString("N") + ".conf");
                    if (new FileInfo(file).Length > 128 * 1024) throw new IOException("WireGuard profile exceeds 128 KiB.");
                    Store.Write(target, File.ReadAllText(file)); candidate.vpns.Add(tag, new Vpn { wireguard_config = target });
                    string config = Path.Combine(Store.Root, "import-" + Guid.NewGuid().ToString("N") + ".json"); bool saved = false;
                    try { Store.Write(config, Store.Json().Serialize(candidate)); Backend.Call("validate", "-c", config); Store.Save(candidate); document = candidate; saved = true; }
                    finally { if (File.Exists(config)) File.Delete(config); if (!saved) File.Delete(target); }
                }, "WireGuard profile imported • Add a rule to choose its traffic");
            }
        }
        private async Task RemoveVpn()
        {
            if (vpns.SelectedItems.Count == 0) return;
            var candidate = Store.Clone(document); candidate.vpns.Remove(vpns.SelectedItems[0].Text); await SaveCandidate(candidate);
        }
        private async Task ImportConfig()
        {
            using (var dialog = new OpenFileDialog { Filter = "RouteBar configuration|*.yaml;*.yml;*.json", CheckFileExists = true })
                if (dialog.ShowDialog(this) == DialogResult.OK) { string file = dialog.FileName; await Work(() => { var candidate = Backend.Load(file); Backend.Call("validate", "-c", file); Store.Save(candidate); document = candidate; }, "Configuration imported"); }
        }
        private void Export()
        {
            using (var dialog = new SaveFileDialog { Filter = "RouteBar JSON|*.json", FileName = "routebar-config.json" })
                if (dialog.ShowDialog(this) == DialogResult.OK) try {
                    string path = Path.GetFullPath(dialog.FileName);
                    if (document.vpns.Values.Any(v => string.Equals(path, Path.GetFullPath(v.wireguard_config), StringComparison.OrdinalIgnoreCase))) throw new IOException("Export must not overwrite a WireGuard profile.");
                    File.WriteAllText(path, Store.Json().Serialize(document), new UTF8Encoding(false));
                } catch (Exception ex) { MessageBox.Show(this, ex.Message, "Export failed"); }
        }
        private async Task ValidateConfiguration()
        {
            var candidate = Store.Clone(document);
            await Work(() => { using (var snapshot = new Connection(candidate)) Log("Rules, WireGuard profiles and bundled engine passed validation."); }, "Valid • Validation did not start the VPN");
        }
        private async Task Connect()
        {
            if (!Backend.IsAdmin)
            {
                try {
                    Store.Save(document);
                    Process.Start(new ProcessStartInfo(Application.ExecutablePath) { UseShellExecute = true, Verb = "runas", WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory });
                    Close();
                } catch (System.ComponentModel.Win32Exception) { status.Text = "Administrator authorization cancelled • You can still edit rules"; }
                return;
            }
            var candidate = Store.Clone(document);
            await Work(() => {
                var next = new Connection(candidate); // Validate before touching a running connection.
                var previous = active;
                try
                {
                    if (previous != null) previous.Stop();
                    next.Start(Log); active = next;
                }
                catch (Exception failure)
                {
                    next.Dispose(); active = null;
                    if (previous != null) {
                        try { previous.Start(Log); active = previous; }
                        catch (Exception rollback) { previous.Dispose(); throw new IOException(failure.Message + " Rollback also failed: " + rollback.Message); }
                    }
                    throw;
                }
                if (previous != null) previous.Dispose();
            }, "Running");
        }
        private async void OnClosing(object sender, FormClosingEventArgs e)
        {
            if (quitting) return;
            e.Cancel = true;
            if (busy) { status.Text = "Wait for the current operation to finish before exiting."; return; }
            busy = true; Enabled = false; timer.Stop(); status.Text = "Disconnecting...";
            try { await Task.Run(() => { if (active != null) { active.Dispose(); active = null; } }); }
            catch (Exception ex) { Log(ex.Message); }
            tray.Visible = false; tray.Dispose(); quitting = true; Close();
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) { timer.Dispose(); tray.Dispose(); }
            base.Dispose(disposing);
        }
    }
    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            if (args.Contains("--self-test")) return SelfTest.Run();
            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm()); return 0;
        }
    }
    internal static class SelfTest
    {
        internal static int Run()
        {
            try
            {
                if (Backend.Quote("C:\\space path\\") != "\"C:\\space path\\\\\"") throw new Exception("argument quoting");
                var doc = new Document(); doc.routing.rules.Add(new Rule { name = "Compound", via = "direct", match = new Selectors { process_names = new[] { "curl.exe" }, domains = new[] { "example.org" } } });
                var copy = Store.Clone(doc); if (copy.routing.rules[0].match.domains[0] != "example.org") throw new Exception("document round trip");
                using (var form = new MainForm()) { form.CreateControl(); if (form.Controls.Count == 0) throw new Exception("window controls"); }
                Console.WriteLine("Windows UI self-test passed."); return 0;
            }
            catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
        }
    }
}
