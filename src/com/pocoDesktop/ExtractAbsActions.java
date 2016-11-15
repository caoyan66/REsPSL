package com.pocoDesktop;

import java.io.File;
import java.io.FilenameFilter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

import com.sun.source.tree.ClassTree;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.NewClassTree;
import com.sun.source.tree.VariableTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.TreeScanner;

public class ExtractAbsActions {
	
	public static Map<String, HashSet<String>> extract(String folderPath) {
		AbsActionVisitor myVisit = new AbsActionVisitor();
		parseAbsActionFiles(getAbsActionFiles(folderPath), myVisit);
		return myVisit.getAbsName2Sigs();
	}

	private static File[] getAbsActionFiles(String folderDir) {
		File folder = new File(folderDir);
		return folder.listFiles(new FilenameFilter() {
			public boolean accept(File dir, String name) {
				return name.endsWith(".java");
			}
		});
	}

	private static void parseAbsActionFiles(File[] files, TreeScanner<Void, Void> scanner) {
		JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
		try (StandardJavaFileManager fileManager = compiler
				.getStandardFileManager(null, null, null)) {
			JavacTask task = (JavacTask) compiler.getTask(null, fileManager,
					null, null, null, fileManager.getJavaFileObjects(files));
			task.parse().forEach(cu -> cu.accept(scanner, null));
		} catch (Exception ex) { }
	}
}

class AbsActionVisitor extends MyVisitor {
	private String absActionName = null;
	private Map<String, HashSet<String>> absName2Sigs;

	public AbsActionVisitor() {
		this.absName2Sigs = new HashMap<String, HashSet<String>>();
	}

	public Map<String, HashSet<String>> getAbsName2Sigs() {
		return absName2Sigs;
	}

	@Override
	public Void visitClass(ClassTree node, Void p) {
		String subClassName = null;
		if (node.getExtendsClause() != null) {
			subClassName = node.getExtendsClause().toString();
			if (subClassName.equals("AbsAction")) {
				absActionName = node.getSimpleName().toString();
				return super.visitClass(node, p);
			}
		}
		return null;
	}

	@Override
	public Void visitMethod(MethodTree node, Void p) {
		if (node.getName().toString().equals("mapConc2Abs"))  {
			List<? extends VariableTree> parameters = node.getParameters();
			if (parameters != null && parameters.size() == 1) {
				if(parameters.get(0).getType().toString().equals("Action")) {
					return super.visitMethod(node, p);
				}
			}
		} 
		return null;
	}

	@Override
	public Void visitMethodInvocation(MethodInvocationTree node, Void p) {
		if (node.getMethodSelect().toString().endsWith(".matches")) {
			List<? extends ExpressionTree> args = node.getArguments();
			if (args!= null && args.size() == 1) {
				String mthStr = actionDeclaration(node.getArguments().get(0).toString(),"Action");
				// successfully located the method signature
				if (mthStr != null && isMethod(mthStr)) {
					if(absName2Sigs.containsKey(absActionName))
						absName2Sigs.get(absActionName).add(mthStr);
					else {
						HashSet<String> newSet = new HashSet<String>();
						newSet.add(mthStr);
						absName2Sigs.put(absActionName, newSet);
					}
				}
			}
		}
		return null;
	}
}

class PreDefinedActions extends MyVisitor {
	private Map<String,String> predefined;
	private String currMtdName = null;

	public PreDefinedActions() {
		this.predefined = new HashMap<String,String>();
	}

	public Map<String,String> getAbsName2Sigs() {
		return predefined;
	}
	
	@Override
	public Void visitMethod(MethodTree node, Void p) {
		currMtdName = node.getName().toString();
		System.out.println("visitMethod - node:" + node);
		super.visitMethod(node, p);
		return null;
	}
	
	public Void visitNewClass(NewClassTree node, Void p) {
		String str = node.toString();
		if(str.length()>0) {
			String mthStr = actionDeclaration(str,"Action");
			// successfully located the method signature
			if (mthStr != null && isMethod(mthStr)) 
				predefined.put("Actions." +currMtdName,mthStr);
		}
		return null;
	}
}

class MyVisitor extends TreeScanner<Void, Void> {
	protected String actionDeclaration(String str, String type) {
		if (str == null) return null;
		
		Pattern pattern = Pattern
				.compile("^\\s*new\\s+"+type+"\\s*\\(\\s*\"(.+)\"\\s*\\)\\s*$");
		Matcher matcher = pattern.matcher(str);
		return matcher.find() ? matcher.group(1).trim() : null;
	}

	protected boolean isMethod(String mtdStr) {
		if (mtdStr == null) return false;
		
		Pattern pattern = Pattern.compile("^(.+)\\((.*)\\)$");
		Matcher matcher = pattern.matcher(mtdStr);
		return matcher.find();
	}
}