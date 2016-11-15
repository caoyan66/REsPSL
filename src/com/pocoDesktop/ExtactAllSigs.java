package com.pocoDesktop;


import java.io.File;
import java.io.FilenameFilter;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

import com.sun.source.util.JavacTask;

public class ExtactAllSigs {
	private Map<String, HashSet<String>> absSigsLookup = null;
	private String folderPath;
	private Set<String> sigs4Act; public Set<String> getSigs4Act() { return sigs4Act;}
	private Set<String> sigs4Res; public Set<String> getSigs4Res() { return sigs4Res;}

	public ExtactAllSigs(String path) {
		this.folderPath = path;
	}

	public void extract() {
		absSigsLookup = ExtractAbsActions.extract(folderPath+"/absActions");
		parsePolicyFiles(getPolicyFiles(folderPath), absSigsLookup);
	}

	private File[] getPolicyFiles(String folderDir) {
		File folder = new File(folderDir);
		return folder.listFiles(new FilenameFilter() {
			public boolean accept(File dir, String name) {
				return name.endsWith(".java");
			}
		});
		
	}

	private void parsePolicyFiles(File[] files, Map<String, HashSet<String>> absSigs) {
		JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
		try (StandardJavaFileManager fileManager = compiler.getStandardFileManager(null, null, null)) {
			JavacTask task = (JavacTask) compiler.getTask(null, fileManager, null, null, null, fileManager.getJavaFileObjects(files));
			PolicyVisitor myVisit = new PolicyVisitor(absSigs);
			task.parse().forEach(cu -> cu.accept(myVisit, null));
			
			sigs4Act = loadAbsActions(myVisit.getActSigs());
			sigs4Res = loadAbsActions(myVisit.getResSigs());
			
		} catch (Exception ex) { 
			ex.printStackTrace(); 
		}
	}

	private Set<String> loadAbsActions(Set<String> sigs) {
		Set<String> updatedSigs = new HashSet<String>();
		if(sigs != null && sigs.size() > 0){
			for(String sig: sigs) {
				if(sig.startsWith("PoCoABS_")) 
					updatedSigs.addAll(absSigsLookup.get(sig.substring(8)));
				else
					updatedSigs.add(sig);
			}
		}
		return updatedSigs;
	}

	public void genAJFile(Set<String> sigs4Act, Set<String> sigs4Res) {
		Set<String> sigs4Evt = new HashSet<String>();
		if(sigs4Act.size()>0 && sigs4Res.size()>0) {
			for(String sig: sigs4Act) {
				if(sigs4Res.contains(sig))
					sigs4Evt.add(sig);
			}
			if(sigs4Evt.size()>0) {
				sigs4Act.removeAll(sigs4Evt);
				sigs4Res.removeAll(sigs4Evt);
			}
		}
		GenAspectJFile genfile = new GenAspectJFile();
		genfile.gen(sigs4Act, sigs4Res, sigs4Evt);
	}
}