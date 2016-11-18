package com.pocoDesktop;
 
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.SpringLayout;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.filechooser.FileNameExtensionFilter;

public class PoCoScanner implements ActionListener, ListSelectionListener, ItemListener {
	private static final int NUM_THREADS = 4;
	
	private final ExecutorService pool;

	private SpringLayout fileSelectionLayout;
	private JFrame appframe;

	private JPanel fileSelectTabPanel;

	private JList<File> fileList;
	private DefaultListModel<File> filesToScan;

	private JPanel fileButtonPanel;
	private JButton addFileButton;
	private JButton removeFileButton;
	
	private JScrollPane fileListScroller;

	private JPanel pocoPanel;
	private JTextField pocoPolicyField;
	private JButton loadPolicyBtn;

	private JButton generateButton;
	private JLabel messageLabel;

	private JList<String> regexList;
	private JList<String> methodList;
	private DefaultListModel<String> list4Methods;
	
	private JPanel statusPanel;

	private JFileChooser classFileChooser;
	private JFileChooser pocoFileChooser;
	private JLabel selectedRegexMethodCountLabel;
	
	private JPanel genAjFileBtnPanel;
	private JButton genAjFileBtn;

	private LinkedHashMap<String, ArrayList<String>> generatedMappings;

	private File pocoFile = null;
	
	private ExtactAllSigs extractHandler;
	private Set<String> sigs4Act;
	private Set<String> sigs4Res;
	private Set<String> sigs4Monitor;

	public PoCoScanner() { 
		SwingUtilities.invokeLater(()->{initializeUI();});
		pool = Executors.newFixedThreadPool(NUM_THREADS);
	}

	public void itemStateChanged(ItemEvent e) {
		boolean selected = false;
		if (e.getStateChange() == ItemEvent.SELECTED) 
			selected = true;
		else if (e.getStateChange() == ItemEvent.DESELECTED) 
			selected = false;
	}

	public void actionPerformed(ActionEvent e) {
		if (e.getSource() == addFileButton) {
			int returnVal = classFileChooser.showOpenDialog(appframe);
			if (returnVal == JFileChooser.APPROVE_OPTION) {
				for (File file : classFileChooser.getSelectedFiles()) {
					filesToScan.addElement(file);
				}
			}

		} else if (e.getSource() == removeFileButton) {
			if (fileList.getSelectedIndices().length > 0) {
				for (int i = fileList.getSelectedIndices().length - 1; i >= 0; i--)
					filesToScan.remove(fileList.getSelectedIndices()[i]);
			} else {
				JOptionPane.showMessageDialog(null, "Please select the policy files that you want to remove first.",
								"Remove File", JOptionPane.WARNING_MESSAGE);
			}
		} else if (e.getSource() == loadPolicyBtn) {
			int returnVal = pocoFileChooser.showOpenDialog(appframe);
			if (returnVal == JFileChooser.APPROVE_OPTION) {
				pocoFile = pocoFileChooser.getSelectedFile();
				pocoPolicyField.setText(pocoFile.getName());
				pocoPolicyField.setToolTipText(pocoFile.getPath());
			}
		} else if (e.getSource() == generateButton) {
			messageLabel.setText("Analysis...");
			addFileButton.setEnabled(false);
			removeFileButton.setEnabled(false);
			loadPolicyBtn.setEnabled(false);
			generateButton.setEnabled(false);
			
			String path = "/Users/yan/Desktop/examplePolicies/";
			extractHandler = new ExtactAllSigs(path);
			extractHandler.extract();
			
			sigs4Act = extractHandler.getSigs4Act();
			sigs4Res = extractHandler.getSigs4Res();
			sigs4Monitor = sigs4Act;
			sigs4Monitor.addAll(sigs4Res);
			for(String sig: sigs4Monitor) {
				list4Methods.addElement(sig);
			}
			messageLabel.setText("Total "+sigs4Monitor.size() + "security-relevant events");
			if(sigs4Monitor.size()>0) {
				methodList.setEnabled(true);
				genAjFileBtn.setEnabled(true);
			}
		} else if (e.getSource() == genAjFileBtn) {
			extractHandler.genAJFile(sigs4Act, sigs4Res);
		}

		if (filesToScan.size() > 0) 
			removeFileButton.setEnabled(true);
		else 
			removeFileButton.setEnabled(false);
	}

	public void valueChanged(ListSelectionEvent e) {
		if (e.getValueIsAdjusting() || regexList.isSelectionEmpty()) 
			return;
		
		String expr = regexList.getSelectedValue();
		ArrayList<String> mappedMethods = generatedMappings.get(expr);
		methodList.setListData(mappedMethods.toArray(new String[0]));
		selectedRegexMethodCountLabel.setText("Count: " + mappedMethods.size());
	}

	public void generateComplete() {
		addFileButton.setEnabled(true);
		removeFileButton.setEnabled(true);
		removeFileButton.setEnabled(true);
		loadPolicyBtn.setEnabled(true);
		generateButton.setEnabled(true);
	}

	public void initializeUI() {
		appframe = new JFrame("PoCo Static Analysis Tool");
		appframe.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		appframe.setBounds(50, 50, 800, 600);
		appframe.setMinimumSize(new Dimension(600, 400));

		// add poco policy files
		classFileChooser = new JFileChooser();
		classFileChooser.setDialogTitle("Add Class Files");
		classFileChooser.setApproveButtonText("Add");
		FileNameExtensionFilter fileFilter = new FileNameExtensionFilter(
				"PoCo Policy files", "poco");
		classFileChooser.setFileFilter(fileFilter);
		classFileChooser.setMultiSelectionEnabled(true);
		classFileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);

		pocoFileChooser = new JFileChooser();
		pocoFileChooser.setDialogTitle("Load PoCo Policy");
		pocoFileChooser.setApproveButtonText("Add");
		FileNameExtensionFilter pocoFileFilter = new FileNameExtensionFilter("PoCo Policy", "poco");
		pocoFileChooser.setFileFilter(pocoFileFilter);
		pocoFileChooser.setMultiSelectionEnabled(false);
		pocoFileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);

		fileSelectionLayout = new SpringLayout();
		fileSelectTabPanel = new JPanel(fileSelectionLayout);
		fileSelectTabPanel.setOpaque(false);

		filesToScan = new DefaultListModel<>();

		fileList = new JList<>(filesToScan);
		fileList.setVisibleRowCount(10);
		fileList.setCellRenderer(new FileRenderer());

		fileListScroller = new JScrollPane(fileList);

		addFileButton = new JButton("Add File");
		removeFileButton = new JButton("Remove File");
		removeFileButton.setEnabled(false);

		addFileButton.addActionListener(this);
		removeFileButton.addActionListener(this);

		fileButtonPanel = new JPanel();
		fileButtonPanel.add(addFileButton);
		fileButtonPanel.add(removeFileButton);
		fileButtonPanel.setOpaque(false);

		// Create panel for regex selection
		pocoPanel = new JPanel(new BorderLayout());
		pocoPanel.setOpaque(false);
		pocoPanel.setBorder(BorderFactory.createTitledBorder("PoCo Policy"));
		pocoPolicyField = new JTextField();
		pocoPolicyField.setEditable(false);
		loadPolicyBtn = new JButton("Load PoCo Policy");
		loadPolicyBtn.addActionListener(this);

		pocoPanel.add(pocoPolicyField, BorderLayout.NORTH);
		pocoPanel.add(loadPolicyBtn, BorderLayout.SOUTH);

		generateButton = new JButton("Extract security-relevant Events");
		generateButton.addActionListener(this);

		messageLabel = new JLabel();

		// Create panel for generation status
		statusPanel = new JPanel();
		statusPanel.setOpaque(false);
		statusPanel.setBorder(BorderFactory.createTitledBorder("Security-Relevant methods:"));
		statusPanel.setEnabled(false); 
		
		list4Methods = new DefaultListModel<String>();
		methodList = new JList<String>(list4Methods);
		methodList.setVisibleRowCount(15);
		//methodList.setCellRenderer(new MethodRenderer());
		methodList.setEnabled(false);
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setViewportView(methodList);
		scrollPane.setPreferredSize(new Dimension(435,345));
		statusPanel.add(scrollPane, BorderLayout.NORTH);
		
		//gen Aj file pane
		genAjFileBtn = new JButton("Generate AJ file");
		genAjFileBtn.addActionListener(this);
		genAjFileBtn.setEnabled(false);
		genAjFileBtnPanel = new JPanel();
		genAjFileBtnPanel.add(messageLabel);
		genAjFileBtnPanel.add(genAjFileBtn);
		genAjFileBtnPanel.setOpaque(false);
		
		setLayout();
		appframe.add(fileSelectTabPanel);
		appframe.setVisible(true);
	}

	private void setLayout() {
		fileSelectTabPanel.add(statusPanel);

		fileSelectTabPanel.add(fileListScroller);
		fileSelectionLayout.putConstraint(SpringLayout.WEST, fileListScroller, 10, SpringLayout.WEST, fileSelectTabPanel);
		fileSelectionLayout.putConstraint(SpringLayout.NORTH, fileListScroller, 10, SpringLayout.NORTH, fileSelectTabPanel);
		fileSelectionLayout.putConstraint(SpringLayout.SOUTH, fileListScroller, -15, SpringLayout.NORTH, fileButtonPanel);
		fileSelectionLayout.putConstraint(SpringLayout.EAST, fileListScroller, -120, SpringLayout.HORIZONTAL_CENTER, fileSelectTabPanel);

		fileSelectTabPanel.add(fileButtonPanel);
		fileSelectionLayout.putConstraint(SpringLayout.SOUTH, fileButtonPanel,-15, SpringLayout.SOUTH, fileSelectTabPanel);
		fileSelectionLayout.putConstraint(SpringLayout.WEST, fileButtonPanel,  15, SpringLayout.WEST, fileSelectTabPanel);
		fileSelectionLayout.putConstraint(SpringLayout.EAST, fileButtonPanel, -75, SpringLayout.HORIZONTAL_CENTER, fileSelectTabPanel);

		fileSelectTabPanel.add(pocoPanel);
		fileSelectionLayout.putConstraint(SpringLayout.WEST, pocoPanel, -90, SpringLayout.HORIZONTAL_CENTER, fileSelectTabPanel);
		fileSelectionLayout.putConstraint(SpringLayout.EAST, pocoPanel, -15, SpringLayout.EAST, fileSelectTabPanel);
		fileSelectionLayout.putConstraint(SpringLayout.NORTH, pocoPanel, 10, SpringLayout.NORTH, fileSelectTabPanel);
		
		//set layout for the generateButton
		fileSelectTabPanel.add(generateButton);
		fileSelectionLayout.putConstraint(SpringLayout.NORTH, generateButton, 5, SpringLayout.SOUTH, pocoPanel);
	    fileSelectionLayout.putConstraint(SpringLayout.EAST, generateButton,-15, SpringLayout.EAST, fileSelectTabPanel);

		fileSelectionLayout.putConstraint(SpringLayout.WEST, statusPanel, -90, SpringLayout.HORIZONTAL_CENTER, fileSelectTabPanel);
		fileSelectionLayout.putConstraint(SpringLayout.EAST, statusPanel, -15, SpringLayout.EAST, fileSelectTabPanel);
		fileSelectionLayout.putConstraint(SpringLayout.NORTH, statusPanel, 40, SpringLayout.SOUTH, pocoPanel); 
	
		fileSelectTabPanel.add(genAjFileBtnPanel);
		fileSelectionLayout.putConstraint(SpringLayout.SOUTH,genAjFileBtnPanel, 50, SpringLayout.SOUTH, statusPanel);
		fileSelectionLayout.putConstraint(SpringLayout.EAST, genAjFileBtnPanel, -10,SpringLayout.EAST, fileSelectTabPanel);
			    
	}

	private static void scanJARFile(File toScan, LinkedHashSet<String> methods) {
		try (JarFile jarFile = new JarFile(toScan)) {
			Enumeration<JarEntry> entries = jarFile.entries();
			ArrayList<JarEntry> jarClassFiles = new ArrayList<>();

			// Find every .class file in JAR
			while (entries.hasMoreElements()) {
				JarEntry entry = entries.nextElement();
				String elementName = entry.getName();
				int extensionStart = elementName.lastIndexOf('.');

				if (extensionStart < 0) {
					continue;
				}

				String extension = elementName.substring(elementName
						.lastIndexOf('.'));

				if (extension.equals(".class")) {
					jarClassFiles.add(entry);
				}
			}

			// // Parse each .class file
			// for(JarEntry classFile : jarClassFiles) {
			// ClassReader reader = new
			// ClassReader(jarFile.getInputStream(classFile));
			// reader.accept(new MethodExtractor(methods), 0);
			// }
		} catch (IOException e) {
			System.out.println("\n\nERROR reading JAR file!");
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
	}

	public static void main(String[] args) { 
		File writeTo = new File("PoCoPolicies.aj");
		//File inputfile = new File("a.txt");
	      try {
			Scanner scan = new Scanner(writeTo);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		new PoCoScanner();
	}

	public void ShowIncompleteWarning() {
		JOptionPane.showMessageDialog( null, "One or more variables have a value that is bound during runtime.\nThe generated mappings may be "
								+ "incomplete.", "Potential Incompleteness",
						JOptionPane.WARNING_MESSAGE);
	}

	private class JavaFileLoader extends SwingWorker<LinkedHashMap<String, ArrayList<String>>, Void> {
		private File[] javaFiles = null;
		private File pocoFileToScan = null;
		private boolean runtimeBoundVar = false;

		public JavaFileLoader(File[] javaFilesToScan, File pocoFileToScan) {
			javaFiles = javaFilesToScan;
			this.pocoFileToScan = pocoFileToScan;
		}

		@Override
		public LinkedHashMap<String, ArrayList<String>> doInBackground() {
			LinkedHashSet<String> methods = new LinkedHashSet<>();

			for (File toScan : javaFiles) {
				String extension = toScan.getName().substring(
						toScan.getName().lastIndexOf('.'));

				if (extension.equals(".jar")) {
					scanJARFile(toScan, methods);
				} else {
					try (FileInputStream classFile = new FileInputStream(toScan)) {
						// ClassReader reader = new ClassReader(classFile);
						// reader.accept(new MethodExtractor(methods), 0);
					} catch (Exception e) {
						System.out.format(
								"ERROR: Problem reading file \"%s\"\n",
								toScan.getName());
						System.out.println(e.getMessage());
						continue;
					}
				}
			}

			String[] regexes = new String[0];

			if (pocoFileToScan == null) {
				return null;
			}

			try {
				extractHandler.extract();
			} catch (Exception ex) {
				ex.printStackTrace();
				System.exit(-1);
			}

			LinkedHashMap<String, ArrayList<String>> mappings = new LinkedHashMap<>(regexes.length);

			final int numRegexes = regexes.length;
			final int regexPerThread = (int) Math.ceil((double) numRegexes / (double) NUM_THREADS);

			ArrayList<MapGenerator> toRun = new ArrayList<>(NUM_THREADS);

			int regexLeft = numRegexes;
			for (int i = 0; i < NUM_THREADS; i++) {
				int numToScan;

				if (regexLeft < regexPerThread) {
					numToScan = regexLeft;
				} else {
					numToScan = regexPerThread;
				}

				toRun.add(new MapGenerator(methods, regexes,
						i * regexPerThread, numToScan));

				regexLeft -= numToScan;
			}

			List<Future<LinkedHashMap<String, ArrayList<String>>>> futures;

			try {
				futures = pool.invokeAll(toRun);
			} catch (InterruptedException e) {
				System.out.println("ERROR in MapGenerator thread");
				e.printStackTrace();
				return null;
			}

			for (Future<LinkedHashMap<String, ArrayList<String>>> future : futures) {
				try {
					mappings.putAll(future.get());
				} catch (InterruptedException | ExecutionException e) {
					e.printStackTrace();
					return null;
				}
			}

			return mappings;
		}

		@Override
		public void done() { 
			try {
				generatedMappings = get();
			} catch (InterruptedException | ExecutionException e) {
				System.out.println("ERROR: Returning from JavaFileLoader execution\n");
				System.out.println(e.getMessage());
				e.printStackTrace();
			}

			if (runtimeBoundVar) 
				ShowIncompleteWarning();

			generateComplete();
		}
	}

	private class MapGenerator implements Callable<LinkedHashMap<String, ArrayList<String>>> {
		private final int startIndex;
		private final int numMaps;
		private final String[] regexList;
		private final LinkedHashSet<String> methodList;

		public MapGenerator(LinkedHashSet<String> methodList,
				String[] regexList, int startIndex, int numMaps) {
			this.startIndex = startIndex;
			this.numMaps = numMaps;
			this.regexList = regexList;
			this.methodList = methodList;
		}

		@Override
		public LinkedHashMap<String, ArrayList<String>> call() {
			LinkedHashMap<String, ArrayList<String>> maps = new LinkedHashMap<>(numMaps);

			for (int i = startIndex; i < startIndex + numMaps; i++) {
				String regex = regexList[i];
				Pattern pat = Pattern.compile(regex);
				ArrayList<String> mappedMethods = new ArrayList<>();

				for (String methodCall : methodList) {
					Matcher match = pat.matcher(methodCall);
					if (match.find()) 
						mappedMethods.add(methodCall);
				}

				maps.put(regex, mappedMethods);
			}
			return maps;
		}
	}
 
}