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
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

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
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpringLayout;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.objectweb.asm.ClassReader;

public class PoCoScanner implements ActionListener, ListSelectionListener, ItemListener {
	private SpringLayout fileSelectionLayout;
	private JFrame appframe;
	private JPanel mainPanel;

	private JList<File> fileList;
	private DefaultListModel<File> filesToScan;

	private JPanel jarClassFilePanel;
	private JFileChooser jarFileChooser;
	
	private JPanel fileButtonPanel;
	private JButton addFileButton;
	private JButton removeFileButton;
	
	private JScrollPane fileListScroller;

	private JPanel pocoPanel;
	private JTextField pocoPolicyField;
	private JButton loadPolicyBtn;
	private JButton extractButton;
	private JTextArea hintTextArea;

	private JList<String> methodList;
	private DefaultListModel<String> list4Methods;
	
	private JPanel methodListPanel;
	private JPanel statusPanel;

	private JFileChooser pocoFileChooser;
	
	private JPanel genAjFileBtnPanel;
	private JButton genAjFileBtn;

	private File pocoFile = null;
	
	private ExtactAllSigs extractHandler;
	private Set<String> sigs4Act;
	private Set<String> sigs4Res;
	private Set<String> sigs4Monitor;
	private LinkedHashSet<String> secRelEvtfromJar;

	public PoCoScanner() { 
		SwingUtilities.invokeLater(()->{initializeUI();});
	}
	
	public static void main(String[] args) {  new PoCoScanner(); }

	public void initializeUI() {
		appframe = new JFrame("PoCo Static Analysis Tool");
		appframe.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		appframe.setBounds(50, 50, 800, 600);
		appframe.setMinimumSize(new Dimension(600, 400));
		fileSelectionLayout = new SpringLayout();
		mainPanel = new JPanel(fileSelectionLayout);
		mainPanel.setOpaque(false);
		
		initial4JarFileChooser();
		initial4PoCoFileChooser();
		initialLeftPanel();
		initialPoCoPanel();
		initialMethodListPanel();
		initialGenAFilePanel();
		initialStatusPanel();
		
		setLayout();
		appframe.add(mainPanel);
		appframe.setResizable(false);
		appframe.setVisible(true);
	}

	private void initialStatusPanel() {
		hintTextArea = new JTextArea();
		hintTextArea.setBorder(null);
		hintTextArea.setText("testing...testing");
		statusPanel = new JPanel(new BorderLayout());
		statusPanel.setOpaque(false);
		statusPanel.setBorder(BorderFactory.createTitledBorder("Generation Stats"));
		statusPanel.add(hintTextArea, BorderLayout.NORTH);
	}
	private void initialGenAFilePanel() {
		genAjFileBtn = new JButton("Generate AJ file");
		genAjFileBtn.addActionListener(this);
		genAjFileBtn.setEnabled(false);
		genAjFileBtnPanel = new JPanel();
		genAjFileBtnPanel.add(genAjFileBtn);
		genAjFileBtnPanel.setOpaque(false);
	}
	private void initialMethodListPanel() {
		methodListPanel = new JPanel();
		methodListPanel.setOpaque(false);
		methodListPanel.setBorder(BorderFactory.createTitledBorder("Security-Relevant methods:"));
		methodListPanel.setEnabled(false); 
		
		list4Methods = new DefaultListModel<String>();
		methodList = new JList<String>(list4Methods);
		methodList.setVisibleRowCount(15);
		//methodList.setCellRenderer(new MethodRenderer());
		methodList.setEnabled(false);
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setViewportView(methodList);
		scrollPane.setPreferredSize(new Dimension(435,325));
		methodListPanel.add(scrollPane, BorderLayout.NORTH);
	}
	private void initialPoCoPanel() {
		pocoPanel = new JPanel(new BorderLayout());
		pocoPanel.setOpaque(false);
		pocoPanel.setBorder(BorderFactory.createTitledBorder("PoCo Policy"));
		pocoPolicyField = new JTextField();
		pocoPolicyField.setEditable(false);
		loadPolicyBtn = new JButton("Load PoCo Policy");
		loadPolicyBtn.addActionListener(this);
		pocoPanel.add(pocoPolicyField, BorderLayout.NORTH);
		pocoPanel.add(loadPolicyBtn, BorderLayout.SOUTH);
		extractButton = new JButton("Extract security-relevant Events");
		extractButton.addActionListener(this);
	}
	private void initialLeftPanel() {
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
		jarClassFilePanel = new JPanel(new BorderLayout());
		jarClassFilePanel.setBorder(BorderFactory.createTitledBorder("Target Application's Jar Files"));
		jarClassFilePanel.add(fileListScroller);
		fileButtonPanel = new JPanel();
		fileButtonPanel.add(addFileButton);
		fileButtonPanel.add(removeFileButton);
		fileButtonPanel.setOpaque(false);
	}
	private void initial4PoCoFileChooser() {
		pocoFileChooser = new JFileChooser();
		pocoFileChooser.setDialogTitle("Load PoCo Policy");
		pocoFileChooser.setApproveButtonText("Add");
		FileNameExtensionFilter pocoFileFilter = new FileNameExtensionFilter("PoCo Policy files", "poco");
		pocoFileChooser.setFileFilter(pocoFileFilter);
		pocoFileChooser.setMultiSelectionEnabled(false);
		pocoFileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
	}
	private void initial4JarFileChooser() {
		jarFileChooser = new JFileChooser();
		jarFileChooser.setDialogTitle("Add Class Files");
		jarFileChooser.setApproveButtonText("Add");
		FileNameExtensionFilter fileFilter = new FileNameExtensionFilter("Compiled Java Classes", "class", "jar");
		jarFileChooser.setFileFilter(fileFilter);
		jarFileChooser.setMultiSelectionEnabled(true);
		jarFileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
	}
	private void setLayout() {
		mainPanel.add(jarClassFilePanel);
		fileSelectionLayout.putConstraint(SpringLayout.NORTH, jarClassFilePanel, 10, SpringLayout.NORTH, mainPanel);
		fileSelectionLayout.putConstraint(SpringLayout.SOUTH, jarClassFilePanel, 0, SpringLayout.NORTH, fileButtonPanel);
		fileSelectionLayout.putConstraint(SpringLayout.WEST, jarClassFilePanel, 10, SpringLayout.WEST, mainPanel);
		fileSelectionLayout.putConstraint(SpringLayout.EAST, jarClassFilePanel, -90, SpringLayout.HORIZONTAL_CENTER, mainPanel);

		mainPanel.add(fileButtonPanel);
		fileSelectionLayout.putConstraint(SpringLayout.SOUTH, fileButtonPanel, -175, SpringLayout.SOUTH, mainPanel);
		fileSelectionLayout.putConstraint(SpringLayout.WEST, fileButtonPanel,  75, SpringLayout.WEST, mainPanel);
		fileSelectionLayout.putConstraint(SpringLayout.EAST, fileButtonPanel, -70, SpringLayout.HORIZONTAL_CENTER, mainPanel);
 	
		mainPanel.add(pocoPanel);
		fileSelectionLayout.putConstraint(SpringLayout.SOUTH, pocoPanel, -80, SpringLayout.SOUTH, mainPanel);
		fileSelectionLayout.putConstraint(SpringLayout.WEST, pocoPanel, 10, SpringLayout.WEST, mainPanel);
		fileSelectionLayout.putConstraint(SpringLayout.EAST, pocoPanel, -90, SpringLayout.HORIZONTAL_CENTER, mainPanel);

		mainPanel.add(extractButton);
		fileSelectionLayout.putConstraint(SpringLayout.SOUTH, extractButton,-45, SpringLayout.SOUTH, mainPanel);
		fileSelectionLayout.putConstraint(SpringLayout.WEST, extractButton, 68, SpringLayout.WEST, mainPanel);
	    //fileSelectionLayout.putConstraint(SpringLayout.EAST, generateButton,-100, SpringLayout.HORIZONTAL_CENTER, mainPanel);
 
		mainPanel.add(methodListPanel);
		fileSelectionLayout.putConstraint(SpringLayout.WEST, methodListPanel, -80, SpringLayout.HORIZONTAL_CENTER, mainPanel);
		fileSelectionLayout.putConstraint(SpringLayout.EAST, methodListPanel, -15, SpringLayout.EAST, mainPanel);
		fileSelectionLayout.putConstraint(SpringLayout.NORTH, methodListPanel, -354, SpringLayout.SOUTH, jarClassFilePanel); 
		fileSelectionLayout.putConstraint(SpringLayout.SOUTH, methodListPanel, 0, SpringLayout.SOUTH, jarClassFilePanel); 
	
		mainPanel.add(genAjFileBtnPanel);
		fileSelectionLayout.putConstraint(SpringLayout.SOUTH,genAjFileBtnPanel, -175, SpringLayout.SOUTH, mainPanel);
		fileSelectionLayout.putConstraint(SpringLayout.EAST, genAjFileBtnPanel, -10, SpringLayout.EAST, mainPanel);
		
		mainPanel.add(statusPanel);
		fileSelectionLayout.putConstraint(SpringLayout.NORTH, statusPanel, 10, SpringLayout.SOUTH, genAjFileBtnPanel); 
		fileSelectionLayout.putConstraint(SpringLayout.WEST, statusPanel, 325, SpringLayout.WEST, mainPanel);
		fileSelectionLayout.putConstraint(SpringLayout.EAST, statusPanel, -20, SpringLayout.EAST, mainPanel);
		fileSelectionLayout.putConstraint(SpringLayout.SOUTH,statusPanel, -50, SpringLayout.SOUTH, mainPanel);
	}
	
	public void actionPerformed(ActionEvent e) { 
		if (e.getSource() == addFileButton) 
			addJarFileAction();
		else if (e.getSource() == removeFileButton) 
			removeSelectedJarFile();
		else if (e.getSource() == loadPolicyBtn)  
			loadPoCoPolicy();
		else if (e.getSource() == extractButton) 
			extractSecRelEvts();
		else if (e.getSource() == genAjFileBtn) 
			extractHandler.genAJFile(sigs4Act, sigs4Res);
		
	}

	private void extractSecRelEvts() {
		hintTextArea.setText("Analysis...");
		addFileButton.setEnabled(false);
		removeFileButton.setEnabled(false);
		loadPolicyBtn.setEnabled(false);
		extractButton.setEnabled(false);
		
		//step 1: extract java file
		File[] files = new File[filesToScan.size()];
		filesToScan.copyInto(files);
		scanJarClassFiles(files);

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
		hintTextArea.setText("Total "+sigs4Monitor.size() + " security-relevant events");
		if(sigs4Monitor.size()>0) {
			methodList.setEnabled(true);
			genAjFileBtn.setEnabled(true);
		}
	}

	private void loadPoCoPolicy() {
		int returnVal = pocoFileChooser.showOpenDialog(appframe);
		if (returnVal == JFileChooser.APPROVE_OPTION) {
			pocoFile = pocoFileChooser.getSelectedFile();
			pocoPolicyField.setText(pocoFile.getName());
			pocoPolicyField.setToolTipText(pocoFile.getPath());
		}
	}

	private void removeSelectedJarFile() {
		if (fileList.getSelectedIndices().length > 0) {
			for (int i = fileList.getSelectedIndices().length - 1; i >= 0; i--)
				filesToScan.remove(fileList.getSelectedIndices()[i]);
		} else {
			JOptionPane.showMessageDialog(null, "Please select the policy files that you want to remove first.",
							"Remove File", JOptionPane.WARNING_MESSAGE);
		}
	}

	private void addJarFileAction() {
		int returnVal = jarFileChooser.showOpenDialog(appframe);
		if (returnVal == JFileChooser.APPROVE_OPTION) {
			for (File file : jarFileChooser.getSelectedFiles()) {
				filesToScan.addElement(file);
			}
		}
		if (filesToScan.size() > 0) 
			removeFileButton.setEnabled(true);
		else 
			removeFileButton.setEnabled(false);
	}
	
	private void scanJarClassFiles(File[] jarClassFiles) {
		LinkedHashSet<String> methods = new LinkedHashSet<>();
		
		for (File toScan : jarClassFiles) {
			String extension = toScan.getName().substring(toScan.getName().lastIndexOf('.'));
			if (extension.equals(".jar")) 
				scanJARFile(toScan, methods);
			else 
				scanClassFile(toScan, methods);
		}

		this.secRelEvtfromJar = methods;
	}
	
	private void scanJARFile(File toScan, LinkedHashSet<String> methods) {
		try (JarFile jarFile = new JarFile(toScan)) {
			Enumeration<JarEntry> entries = jarFile.entries();
			ArrayList<JarEntry> jarClassFiles = new ArrayList<>();
			
			while (entries.hasMoreElements()) {
				JarEntry entry = entries.nextElement();
				String elementName = entry.getName();
				int extensionStart = elementName.lastIndexOf('.');
				if (extensionStart < 0)  continue;
				String extension = elementName.substring(elementName.lastIndexOf('.'));
				if (extension.equals(".class"))  
					jarClassFiles.add(entry);
			}

			for(JarEntry classFile : jarClassFiles) {
				 ClassReader reader = new ClassReader(jarFile.getInputStream(classFile));
				 reader.accept(new MethodExtractor(methods), 0);
				 test(methods);
			}
		} catch (IOException e) {
			System.out.println("\n\nERROR reading JAR file!");
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
	}

	private void scanClassFile(File toScan, LinkedHashSet<String> methods) {
		try (FileInputStream classFile = new FileInputStream(toScan)) {
			 ClassReader reader = new ClassReader(classFile);
			 reader.accept(new MethodExtractor(methods), 0);
		} catch (Exception e) {
			System.out.format("ERROR: Problem reading file \"%s\"\n", toScan.getName());
			System.out.println(e.getMessage());
		}
	}
	
	private void test(LinkedHashSet<String> methods) {
		File writeTo = new File("methods.txt");
		try (PrintWriter out = new PrintWriter(writeTo)){
			for(String str: methods)
				 out.format(str);
		} catch (FileNotFoundException e) { 
			e.printStackTrace();
		}  
	}
	public void itemStateChanged(ItemEvent e) {}
	public void valueChanged(ListSelectionEvent e) { }
}