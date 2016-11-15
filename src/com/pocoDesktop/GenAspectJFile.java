package com.pocoDesktop;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GenAspectJFile {
	private PrintWriter out;
	private final int indentLevel = 0;
	private static int pointCount = 0;
	
	public void gen(Set<String> actSigs,Set<String> resSigs,Set<String> evtSigs) {
		File writeTo = new File("PoCoPolicies.aj");
		try {
			out = new PrintWriter(writeTo);
			//step 1: aspectjPrologue
			outAspectJPrologue();
	        //step 2: add pointcut for monitoring reflection events, only allow poco to do so
	        genPt4Reflect(); 
	        //step 3: generate advice for not-promoted action
	        genPointCut4Actions(actSigs);
	        //step 4: generate advice for not-promoted result
	        genPointCut4Results(resSigs);
	        //step 5: generate advices for those methods that need monitor both before and after proceed
	        genPointCut4Events(evtSigs);
	        //setp 6: generate advice for promoted action
	        outAdvicePrologue4Result();
	        outAdviceInvokeConstructor();
	        outAspectJEpilogue();
			
		} catch (FileNotFoundException e) { e.printStackTrace();}
		finally{
			out.close();
		}
	}
	
	private void outAspectJEpilogue() {
		outLine(0, "}");
	}

	private void outAspectJPrologue() {
        outLine(0, "package com.poco.demo;\n");
        outLine(0, "import java.lang.reflect.Method;");
        outLine(0, "import java.lang.reflect.Constructor;\n");
        outLine(0, "import com.poco.event.Action;");
        outLine(0, "import com.poco.event.Result;");
        outLine(0, "import com.poco.policy.PoCo;");
        outLine(0, "import com.poco.policy.RootPolicy;");
        outLine(0, "import com.poco.policy.examplePolicies.*;");
        outLine(0, "import com.poco.sre.SRE;\n");

        outLine(0, "public aspect PoCoPolicies {");
        outLine(1, "private RootPolicy root = new RootPolicy();\n");
        outLine(1, "public PoCoPolicies() {");
        //add policies? ...
        outLine(1, "}\n");
    }
	
	private void genPt4Reflect() {
        outLine(1, "pointcut PC4Reflection():");
        outLine(2, "call (* Method.invoke(Object, Object...)) && !within(com.poco.runtime.*);\n");
        outLine(1, "Object around(): PC4Reflection()   { ");
        outLine(2, "return new SRE(null, Action.AnyAction); ");
        outLine(1, "}\n");
    }
	
	private void genPointCut4Actions(Set<String> sigs) { genPointCuts(sigs, 0); }
    private void genPointCut4Results(Set<String> sigs) { genPointCuts(sigs, 1); }
    private void genPointCut4Events(Set<String> sigs)  { genPointCuts(sigs, 2); }
	 
    private void genPointCuts(Set<String> sigs, int mode) {
    	Set<String> temp = new HashSet<String>();
    	for(String sig: sigs) {
    		if(!isAction(sig))  temp.add(sig);
    	}
    	sigs.removeAll(temp);
    	if(sigs.size()==0) return;
    	
    	outLine(1, "pointcut PointCut%s():", pointCount);
    	StringBuilder sb = new StringBuilder();
    	int count = 0;
    	for(String sig: sigs) {
    		if(count != 0) sb.append("\t\t");
    		sb.append("call(");
    		if(!isConstructor(sig)) sb.append("* ");
    		sb.append(sig + ")");
    		if(++count<sigs.size())
    			sb.append(" || \n");
    	}
    	outLine(2, "%s && !within(com.poco.runtime.*);\n", sb.toString());
    	
    	if(mode ==0) { //action
			outLine(1, "Object around(): PointCut%s() {",pointCount++);
			outLine(2, "root.query(new Action(thisJoinPoint));");
			outLine(2, "if(root.hasRes4Action())");
			outLine(3, "return root.getRes4Action();");
			outLine(2, "else");
			outLine(3, "return proceed();");
		}else  {
			outLine(1, "Object around(): PointCut%s() {",pointCount++);
			if(mode ==2)
				outLine(2, "root.query(new Action(thisJoinPoint.getSignature()).setArgs(thisJoinPoint.getArgs()));");
	        outLine(2, "Result result = new Result(thisJoinPoint).setRes(proceed());");
	        outLine(2, "root.query(result);");
	        outLine(2, "return result.getEvtRes();");
		} 
    	outLine(1, "}\n");
    }
    
    private void outAdvicePrologue4Result() {
    	outLine(1, "pointcut PointCut%d(Method run):", pointCount);
    	outLine(2, "target(run) &&call(Object Method.invoke(..));\n");

        outLine(1, "Object around(Method run): PointCut%s(run) {", pointCount++);
        outLine(2, "Object ret = proceed(run);");
        outLine(2, "Result promRes = new Result(run).setRes(ret);");
        outLine(2, "root.query(promRes);");
        outLine(2, "return promRes.getEvtRes();");
        outLine(1, "}\n");
    }

    private void outAdviceInvokeConstructor() {
    	outLine(1, "pointcut PointCut%d(Constructor run):", pointCount);
    	outLine(2, "target(run) && call(* Constructor.newInstance(..));\n");
    	
        outLine(1, "Object around(Constructor run): PointCut%s(run) {", pointCount++);
        outLine(2, "Object ret = proceed(run);");
        outLine(2, "Result promRes = new Result(run).setRes(ret);");
        outLine(2, "root.query(promRes);");
        outLine(2, "return promRes.getEvtRes();");
        outLine(1, "}\n");
    }
    
	private boolean isConstructor(String sig) {
		Pattern pat = Pattern.compile("^(.+)\\.new\\((.*)\\)$");
		Matcher matcher = pat.matcher(sig);
		return matcher.find();
	}

	private boolean isAction(String str) {
		if (str == null)
			return false;
		Pattern pattern = Pattern.compile("^(.+)\\((.*)\\)$");
		Matcher matcher = pattern.matcher(str);
		return matcher.find();
	}
	
	/**
     * Outputs one line of Java/AspectJ code to the out object (always ends in newline).
     *
     * @param indent indent level of current line (relative to the existing indent level)
     * @param text   code to write out (printf style formatting used)
     * @param args   printf-style arguments
     */
    private void outLine(int indent, String text, Object... args) {
        outPartial(indent, text, args);
        outPartial(-1, "\n");
    }
    
    private void outPartial(int indent, String text, Object... args) {
        if (indent >= 0) {
            int trueIndent = (indent + indentLevel) * 4;
            for (int i = 0; i < trueIndent; i++)
                out.format(" ");
        }
        out.format(text, args);
    }
}
