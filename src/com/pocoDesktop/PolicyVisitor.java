package com.pocoDesktop;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Stack;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.sun.source.tree.BlockTree;
import com.sun.source.tree.ClassTree;
import com.sun.source.tree.ExpressionStatementTree;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.IfTree;
import com.sun.source.tree.LambdaExpressionTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.NewClassTree;
import com.sun.source.tree.ReturnTree;
import com.sun.source.tree.StatementTree;
import com.sun.source.tree.Tree;
import com.sun.source.tree.Tree.Kind;
import com.sun.source.tree.VariableTree;
import com.sun.source.util.TreeScanner;

class PolicyVisitor extends TreeScanner<Void, Void> {
	//private static boolean DBG = true;
	private Map<String, HashSet<String>> absSigsLookup;
	private Map<String, String> symbolTable;
	private static Stack<Integer> flag4Lambda;

	private Set<String> actSigs;
	public Set<String> getActSigs() { return actSigs;}
	private Set<String> resSigs;
	public Set<String> getResSigs() { return resSigs; }

	public PolicyVisitor(Map<String, HashSet<String>> absSigs) {
		this.absSigsLookup = absSigs;
		flag4Lambda = new Stack<>();
		resetSigSets();
	}

	private void resetSigSets() {
		this.actSigs = new HashSet<String>();
		this.resSigs = new HashSet<String>();
	}

	@Override
	public Void visitClass(ClassTree node, Void p) {
		if (node.getExtendsClause() != null) {
			// only parse policy classes
			if (node.getExtendsClause().toString().equals("Policy")) {
//				if (DBG) {
//					System.out.println("\nAnalysing the " + node.getSimpleName() + " policy ......");
//				}
				symbolTable = new HashMap<String, String>();
				super.visitClass(node, p); 
				return null;
			}
		}
		return null;
	}

	public Void visitVariable(VariableTree node, Void p) {
		String varType = node.getType().toString();
		switch (varType) {
		case "Action":
			ExpressionTree actionVar = node.getInitializer();
			if (actionVar != null && actionVar.getKind().toString().equals("NEW_CLASS")) {
				NewClassTree classTree = (NewClassTree) actionVar;
				String actionName = classTree.getIdentifier().toString();
				// if it is new action case, get the signature
				if (actionName.equals("Action")) {
					List<? extends Tree> args = classTree.getArguments();
					if (isActionDeclare(args)) {
						String sig = getSigFromActDeclartion(args);
						if (isValidMethodSig(sig))
							this.symbolTable.put(node.getName().toString(), "PoCoAct_" + sig);
					}
				} else if (isAbsActionDeclaration(actionName)) { // absaction case
					this.symbolTable.put(node.getName().toString(), "PoCoABS_" + actionName);
				}
			}
			break;
		case "Result":
			ExpressionTree resultVar = node.getInitializer();
			if (resultVar != null
					&& resultVar.getKind().toString().equals("NEW_CLASS")) {
				NewClassTree classTree = (NewClassTree) resultVar;
				String actionName = classTree.getIdentifier().toString();
				// if it is new action case, get the signature
				if (actionName.equals("Result")) {
					List<? extends Tree> args = classTree.getArguments();
					if (isActionDeclare(args)) {
						String sig = getSigFromActDeclartion(args);
						if (isValidMethodSig(sig))
							this.symbolTable.put(node.getName().toString(), "PoCoRes_"+sig);
					}
				}
			}
			break;
		default:
			break;
		}
		return super.visitVariable(node, p);
	}

	private String getSigFromActDeclartion(List<? extends Tree> args) {
		if (args != null && args.size() == 1) {
			String sig = args.get(0).toString();
			if (sig.length() > 2) {
				sig = sig.substring(1, sig.length() - 1);
				return sig;
			}
		}
		return null;
	}

	private boolean isActionDeclare(List<? extends Tree> args) {
		if (args != null && args.size() == 1) {
			if (args.get(0).getKind() == Kind.STRING_LITERAL)
				return true;
		}
		return false;
	}

	private boolean isAbsActionDeclaration(String absActionName) {
		return this.absSigsLookup != null && absSigsLookup.containsKey(absActionName);
	}
  

//	private void handleOtherCase4VisitVar(Kind kind, String varName,String varType, String val) {
//		switch (kind) {
//		case INT_LITERAL:
//			updateSymbolTable(varName, varType, Integer.parseInt(val));
//			break;
//		case LONG_LITERAL:
//			updateSymbolTable(varName, varType, Long.parseLong(val));
//			break;
//		case FLOAT_LITERAL:
//			updateSymbolTable(varName, varType, Float.parseFloat(val));
//			break;
//		case DOUBLE_LITERAL:
//			updateSymbolTable(varName, varType, Double.parseDouble(val));
//			break;
//		case BOOLEAN_LITERAL:
//			updateSymbolTable(varName, varType, Boolean.parseBoolean(val));
//			break;
//		case CHAR_LITERAL:
//			updateSymbolTable(varName, varType, val.charAt(0));
//			break;
//		default:
//			break;
//		}
//	}

	@Override
	public Void visitMethod(MethodTree node, Void p) {
		// only need parse constructor method
		if (node.getName().toString().equals("policyLambda")) {
			List<? extends VariableTree> parameter = node.getParameters();
			if (parameter != null && parameter.size() == 1) {
				Tree varType = parameter.get(0).getType();
				if (varType != null && varType.toString().equals("Event")) {
					// var name, var type
					this.symbolTable.put(parameter.get(0).getName().toString(),
							varType.toString());
					super.visitMethod(node, p);
				}
			}
		}
		return null;
	}

	@Override
	public Void visitLambdaExpression(LambdaExpressionTree node, Void p) {
		if (node.getBodyKind().toString().equals("STATEMENT")) {
			flag4Lambda.push(1);
			BlockTree statement = (BlockTree) node.getBody();
			visitBlock(statement, p);
			flag4Lambda.pop();
		}
		// }
		return null;
	}

	public Void visitBlock(BlockTree node, Void p) {
		if (!flag4Lambda.isEmpty() && flag4Lambda.peek() == 1) {
			List<? extends StatementTree> statements = node.getStatements();
			for (StatementTree st : statements) {
				switch (st.getKind()) {
				case IF:
					visitIf((IfTree) st, p);
					break;
				case RETURN:
					visitReturn((ReturnTree) st, p);
					break;
				case EXPRESSION_STATEMENT:
					visitExpressionStatement((ExpressionStatementTree) st, p);
					break;
				default:
					break;
				}
			}
			return null;
		} else
			return super.visitBlock(node, p);
	}

	@Override
	public Void visitIf(IfTree node, Void p) {
		super.visitIf(node, p);
		return null;
	}

//	@Override
//	public Void visitReturn(ReturnTree node, Void p) {
//		flag4Return.push(1);
//		super.visitReturn(node, p);
//		flag4Return.pop();
//		return null;
//	}

	@Override
	public Void visitMethodInvocation(MethodInvocationTree node, Void p) {
		if (node.getMethodSelect().toString().endsWith(".matches")) {
			List<? extends ExpressionTree> args = node.getArguments();
			if(args != null && args.size() ==1) {
				switch(args.get(0).getKind()){
				case IDENTIFIER:
					String var = args.get(0).toString();
					if(symbolTable.containsKey(var)) {
						String sig = symbolTable.get(var);
						add2Sigs(sig);
					}
					break;
				case NEW_CLASS:
					NewClassTree arg = (NewClassTree) args.get(0);
					String declaredType = arg.getIdentifier().toString();
					
					if(declaredType.equals("Action") || declaredType.equals("Result")) {
						if (isActionDeclare(arg.getArguments())) {
							String sig = getSigFromActDeclartion(args);
							if (isValidMethodSig(sig)) {
								if(declaredType.equals("Action"))
									this.actSigs.add(sig);
								else
									this.resSigs.add(sig);
							}
						}
					}else if(isAbsActionDeclaration(declaredType)){
						this.actSigs.add("PoCoABS_"+declaredType);
					}
					break;
					
				default:
					break;
				}
			}
		}
		return super.visitMethodInvocation(node, p);
	}

	private void add2Sigs(String sig) {
		if(sig.startsWith("PoCoAct_"))
			this.actSigs.add(sig.substring(8));
		else if(sig.startsWith("PoCoRes_"))
			this.resSigs.add(sig.substring(8));
		else 
			this.actSigs.add(sig);
	}

	private boolean isValidMethodSig(String sig) {
		if (sig == null)
			return false;
		Pattern pattern = Pattern.compile("^(.+)\\((.*)\\)$");
		Matcher matcher = pattern.matcher(sig);
		return matcher.find();
	}
}