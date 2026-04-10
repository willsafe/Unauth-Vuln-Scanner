package com.example.tool;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingWorker;
import javax.swing.WindowConstants;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

@SuppressWarnings({"serial", "this-escape"})
public class MainWindow extends JFrame {
    private final VulnerabilityScanner scanner = new VulnerabilityScanner();
    private final List<ServiceCheck> serviceChecks = scanner.getServiceChecks();
    private final List<ServiceCheck> specialChecks = scanner.getSpecialChecks();
    private final Map<String, JCheckBox> serviceCheckboxes = new LinkedHashMap<String, JCheckBox>();
    private final Map<String, JCheckBox> specialCheckboxes = new LinkedHashMap<String, JCheckBox>();

    private final JTextArea targetArea = new JTextArea(4, 40);
    private final JTextField filePathField = new JTextField(35);
    private final JSpinner threadSpinner = new JSpinner(new SpinnerNumberModel(20, 1, 100, 1));
    private final JSpinner timeoutSpinner = new JSpinner(new SpinnerNumberModel(5, 1, 30, 1));
    private final JCheckBox proxyEnabledCheck = new JCheckBox("启用SOCKS5");
    private final JTextField proxyHostField = new JTextField("127.0.0.1", 10);
    private final JSpinner proxyPortSpinner = new JSpinner(new SpinnerNumberModel(7890, 1, 65535, 1));
    private final JButton proxyApplyButton = new JButton("应用全局代理");
    private final JLabel statusLabel = new JLabel("准备就绪");
    private final JLabel countLabel = new JLabel("已选: 0 个服务");
    private final JProgressBar progressBar = new JProgressBar(0, 100);

    private final DefaultTableModel tableModel = new DefaultTableModel(new Object[] {"目标", "漏洞类型", "状态", "详细信息", "时间"}, 0) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };
    private final JTable resultTable = new JTable(tableModel);

    private final JButton startButton = new JButton("开始扫描");
    private final JButton stopButton = new JButton("停止");

    private final List<ScanRecord> records = new ArrayList<ScanRecord>();
    private ScanWorker worker;

    public MainWindow() {
        setTitle("未授权漏洞扫描器(Java) | 仅供安全研究，请勿用于未授权测试，后果自负");
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setSize(1120, 760);
        setLocationRelativeTo(null);
        initUi();
    }

    private void initUi() {
        JPanel root = new JPanel(new BorderLayout(10, 10));
        root.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        setContentPane(root);

        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));

        JPanel targetPanel = new JPanel(new BorderLayout(8, 8));
        targetPanel.setBorder(BorderFactory.createTitledBorder("目标"));
        targetArea.setLineWrap(true);
        targetArea.setWrapStyleWord(true);
        targetArea.setText("127.0.0.1");
        targetPanel.add(new JScrollPane(targetArea), BorderLayout.CENTER);

        JPanel filePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        filePathField.setEditable(false);
        JButton browseButton = new JButton("选择目标文件");
        browseButton.addActionListener(e -> browseTargetFile());
        filePanel.add(filePathField);
        filePanel.add(browseButton);
        targetPanel.add(filePanel, BorderLayout.SOUTH);
        top.add(targetPanel);

        JPanel configPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        configPanel.setBorder(BorderFactory.createTitledBorder("扫描配置"));
        configPanel.add(new JLabel("线程:"));
        configPanel.add(threadSpinner);
        configPanel.add(new JLabel("超时(秒):"));
        configPanel.add(timeoutSpinner);
        configPanel.add(proxyEnabledCheck);
        configPanel.add(new JLabel("代理地址:"));
        configPanel.add(proxyHostField);
        configPanel.add(new JLabel("端口:"));
        configPanel.add(proxyPortSpinner);
        configPanel.add(proxyApplyButton);
        configPanel.add(countLabel);
        proxyEnabledCheck.addActionListener(e -> updateProxyControlState());
        proxyApplyButton.addActionListener(e -> applyProxySettings(false));
        top.add(configPanel);

        JPanel servicePanel = new JPanel(new BorderLayout());
        servicePanel.setBorder(BorderFactory.createTitledBorder("服务探测"));
        JPanel serviceGrid = new JPanel(new GridLayout(0, 5, 8, 8));
        for (ServiceCheck check : serviceChecks) {
            JCheckBox cb = new JCheckBox(check.getDisplayName(), true);
            cb.addActionListener(e -> updateSelectedCount());
            serviceCheckboxes.put(check.getKey(), cb);
            serviceGrid.add(cb);
        }
        JScrollPane serviceScroll = new JScrollPane(serviceGrid);
        serviceScroll.setPreferredSize(new Dimension(1000, 220));
        servicePanel.add(serviceScroll, BorderLayout.CENTER);

        JPanel serviceOps = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton selectAll = new JButton("全部选中");
        JButton selectNone = new JButton("全部取消");
        selectAll.addActionListener(e -> setAllServices(true));
        selectNone.addActionListener(e -> setAllServices(false));
        serviceOps.add(selectAll);
        serviceOps.add(selectNone);
        servicePanel.add(serviceOps, BorderLayout.SOUTH);
        top.add(servicePanel);

        JPanel specialPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        specialPanel.setBorder(BorderFactory.createTitledBorder("扩展检测"));
        for (ServiceCheck check : specialChecks) {
            JCheckBox cb = new JCheckBox(check.getDisplayName(), true);
            specialCheckboxes.put(check.getKey(), cb);
            specialPanel.add(cb);
        }
        top.add(specialPanel);

        root.add(top, BorderLayout.NORTH);

        JPanel center = new JPanel(new BorderLayout(8, 8));
        center.setBorder(BorderFactory.createTitledBorder("扫描结果"));
        resultTable.getColumnModel().getColumn(0).setPreferredWidth(200);
        resultTable.getColumnModel().getColumn(1).setPreferredWidth(150);
        resultTable.getColumnModel().getColumn(2).setPreferredWidth(80);
        resultTable.getColumnModel().getColumn(3).setPreferredWidth(450);
        resultTable.getColumnModel().getColumn(4).setPreferredWidth(100);
        center.add(new JScrollPane(resultTable), BorderLayout.CENTER);
        root.add(center, BorderLayout.CENTER);

        JPanel bottom = new JPanel(new BorderLayout(8, 8));
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        startButton.addActionListener(e -> startScan());
        stopButton.addActionListener(e -> stopScan());
        stopButton.setEnabled(false);

        JButton exportCsv = new JButton("导出CSV");
        exportCsv.addActionListener(e -> exportCsv());
        JButton clearBtn = new JButton("清空结果");
        clearBtn.addActionListener(e -> clearResults());

        buttons.add(startButton);
        buttons.add(stopButton);
        buttons.add(exportCsv);
        buttons.add(clearBtn);
        bottom.add(buttons, BorderLayout.WEST);

        JPanel statusPanel = new JPanel(new BorderLayout(8, 8));
        progressBar.setValue(0);
        statusPanel.add(progressBar, BorderLayout.CENTER);
        statusPanel.add(statusLabel, BorderLayout.SOUTH);
        bottom.add(statusPanel, BorderLayout.CENTER);
        root.add(bottom, BorderLayout.SOUTH);

        updateProxyControlState();
        updateSelectedCount();
    }

    private void browseTargetFile() {
        JFileChooser chooser = new JFileChooser();
        int ret = chooser.showOpenDialog(this);
        if (ret == JFileChooser.APPROVE_OPTION) {
            filePathField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void setAllServices(boolean checked) {
        for (JCheckBox cb : serviceCheckboxes.values()) {
            cb.setSelected(checked);
        }
        updateSelectedCount();
    }

    private void updateSelectedCount() {
        int count = 0;
        for (JCheckBox cb : serviceCheckboxes.values()) {
            if (cb.isSelected()) {
                count++;
            }
        }
        countLabel.setText("已选: " + count + " 个服务");
    }

    private void updateProxyControlState() {
        boolean enabled = proxyEnabledCheck.isSelected();
        proxyHostField.setEnabled(enabled);
        proxyPortSpinner.setEnabled(enabled);
    }

    private boolean applyProxySettings(boolean silent) {
        if (!proxyEnabledCheck.isSelected()) {
            scanner.clearProxy();
            if (!silent) {
                statusLabel.setText("代理已关闭，当前模式: " + scanner.getProxyLabel());
            }
            return true;
        }
        String host = proxyHostField.getText() == null ? "" : proxyHostField.getText().trim();
        int port = (Integer) proxyPortSpinner.getValue();
        if (host.isEmpty()) {
            JOptionPane.showMessageDialog(this, "请输入 SOCKS5 代理地址");
            return false;
        }
        scanner.setSocks5Proxy(host, port);
        if (!silent) {
            statusLabel.setText("代理已生效: " + scanner.getProxyLabel());
        }
        return true;
    }

    private void startScan() {
        if (worker != null && !worker.isDone()) {
            JOptionPane.showMessageDialog(this, "已有扫描任务在运行");
            return;
        }
        if (!applyProxySettings(true)) {
            return;
        }
        Set<String> targets = collectTargets();
        if (targets.isEmpty()) {
            JOptionPane.showMessageDialog(this, "请输入目标或选择目标文件");
            return;
        }

        List<ServiceCheck> selectedChecks = collectSelectedChecks();
        if (selectedChecks.isEmpty()) {
            JOptionPane.showMessageDialog(this, "请至少选择一个探测项");
            return;
        }

        clearResults();
        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        statusLabel.setText("扫描中...");
        progressBar.setValue(0);

        int threads = (Integer) threadSpinner.getValue();
        int timeoutMs = (Integer) timeoutSpinner.getValue() * 1000;
        worker = new ScanWorker(targets, selectedChecks, threads, timeoutMs);
        worker.execute();
    }

    private void stopScan() {
        if (worker != null) {
            worker.requestStop();
        }
    }

    private void clearResults() {
        records.clear();
        tableModel.setRowCount(0);
    }

    private Set<String> collectTargets() {
        List<String> fileLines = null;
        String path = filePathField.getText().trim();
        if (!path.isEmpty()) {
            try {
                fileLines = Files.readAllLines(new File(path).toPath(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "读取目标文件失败: " + e.getMessage());
                return new LinkedHashSet<String>();
            }
        }
        return scanner.parseTargets(targetArea.getText(), fileLines);
    }

    private List<ServiceCheck> collectSelectedChecks() {
        List<ServiceCheck> checks = new ArrayList<ServiceCheck>();
        for (ServiceCheck check : serviceChecks) {
            JCheckBox cb = serviceCheckboxes.get(check.getKey());
            if (cb != null && cb.isSelected()) {
                checks.add(check);
            }
        }
        for (ServiceCheck check : specialChecks) {
            JCheckBox cb = specialCheckboxes.get(check.getKey());
            if (cb != null && cb.isSelected()) {
                checks.add(check);
            }
        }
        return checks;
    }

    private void addRecord(ScanRecord record) {
        records.add(record);
        tableModel.addRow(new Object[] {
            record.getTarget(),
            record.getCheckName(),
            record.getStatus(),
            record.getMessage(),
            record.getTime()
        });
    }

    private void exportCsv() {
        if (records.isEmpty()) {
            JOptionPane.showMessageDialog(this, "暂无结果可导出");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("scan-result.csv"));
        int ret = chooser.showSaveDialog(this);
        if (ret != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File file = chooser.getSelectedFile();
        try (BufferedWriter writer = Files.newBufferedWriter(file.toPath(), StandardCharsets.UTF_8)) {
            writer.write("目标,漏洞类型,状态,详细信息,时间");
            writer.newLine();
            for (ScanRecord r : records) {
                writer.write(csv(r.getTarget()) + "," + csv(r.getCheckName()) + "," + csv(r.getStatus()) + "," + csv(r.getMessage()) + "," + csv(r.getTime()));
                writer.newLine();
            }
            JOptionPane.showMessageDialog(this, "导出成功: " + file.getAbsolutePath());
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "导出失败: " + e.getMessage());
        }
    }

    private String csv(String text) {
        String v = text == null ? "" : text;
        String escaped = v.replace("\"", "\"\"");
        return "\"" + escaped + "\"";
    }

    private class ScanWorker extends SwingWorker<Void, UiEvent> {
        private final List<TargetInfo> targets = new ArrayList<TargetInfo>();
        private final List<ServiceCheck> checks;
        private final int threads;
        private final int timeoutMs;
        private final AtomicBoolean stop = new AtomicBoolean(false);
        private final AtomicInteger completed = new AtomicInteger(0);
        private final AtomicInteger vulnCount = new AtomicInteger(0);
        private final int totalChecks;

        ScanWorker(Set<String> rawTargets, List<ServiceCheck> checks, int threads, int timeoutMs) {
            this.checks = checks;
            this.threads = threads;
            this.timeoutMs = timeoutMs;
            for (String raw : rawTargets) {
                TargetInfo t = scanner.parseTarget(raw);
                if (t != null) {
                    targets.add(t);
                }
            }
            this.totalChecks = targets.size() * checks.size();
        }

        void requestStop() {
            stop.set(true);
            cancel(true);
        }

        @Override
        protected Void doInBackground() {
            if (targets.isEmpty()) {
                publish(new UiEvent("没有可用目标", 0, 0, null));
                return null;
            }
            ExecutorService pool = Executors.newFixedThreadPool(threads);
            List<Future<?>> futures = new ArrayList<Future<?>>();

            for (TargetInfo target : targets) {
                futures.add(pool.submit(() -> {
                    for (ServiceCheck check : checks) {
                        if (stop.get() || isCancelled()) {
                            break;
                        }
                        CheckOutcome outcome = check.getChecker().check(target, timeoutMs);
                        int done = completed.incrementAndGet();
                        ScanRecord record = null;
                        if (outcome.isVulnerable()) {
                            int found = vulnCount.incrementAndGet();
                            String time = new SimpleDateFormat("HH:mm:ss", Locale.ROOT).format(new Date());
                            record = new ScanRecord(target.getInput(), check.getDisplayName(), "漏洞", outcome.getMessage(), time);
                            publish(new UiEvent("扫描中... 已发现漏洞: " + found, done, totalChecks, record));
                        } else {
                            publish(new UiEvent("扫描中...", done, totalChecks, null));
                        }
                    }
                }));
            }

            for (Future<?> future : futures) {
                if (stop.get() || isCancelled()) {
                    break;
                }
                try {
                    future.get();
                } catch (Exception ignored) {
                }
            }
            pool.shutdownNow();
            return null;
        }

        @Override
        protected void process(List<UiEvent> chunks) {
            if (chunks.isEmpty()) {
                return;
            }
            for (UiEvent event : chunks) {
                if (event.record != null) {
                    addRecord(event.record);
                }
            }
            UiEvent last = chunks.get(chunks.size() - 1);
            int pct = last.total <= 0 ? 0 : (int) (last.done * 100.0 / last.total);
            progressBar.setValue(pct);
            statusLabel.setText(last.message + " | 进度: " + last.done + "/" + last.total + " | 漏洞: " + vulnCount.get());
        }

        @Override
        protected void done() {
            startButton.setEnabled(true);
            stopButton.setEnabled(false);
            int doneCount = completed.get();
            int vuln = vulnCount.get();
            if (stop.get() || isCancelled()) {
                statusLabel.setText("扫描已停止 | " + scanner.getProxyLabel() + " | 完成: " + doneCount + " | 漏洞: " + vuln);
            } else {
                progressBar.setValue(100);
                statusLabel.setText("扫描完成 | " + scanner.getProxyLabel() + " | 完成: " + doneCount + " | 漏洞: " + vuln);
                JOptionPane.showMessageDialog(MainWindow.this, "扫描完成\n检测项: " + doneCount + "\n发现漏洞: " + vuln);
            }
        }
    }

    private static class UiEvent {
        private final String message;
        private final int done;
        private final int total;
        private final ScanRecord record;

        private UiEvent(String message, int done, int total, ScanRecord record) {
            this.message = message;
            this.done = done;
            this.total = total;
            this.record = record;
        }
    }
}
