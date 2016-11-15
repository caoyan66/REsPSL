package com.pocoDesktop; 

public class VariableVisitor {// extends PoCoParserBaseVisitor<String> {
//    public VariableBox variableBox = new VariableBox();
//    private Variable currentVariable;
//    private Stack<VariablePart> currentParts = new Stack<>();
//    private Stack<IVarPartCollection> partCollectors = new Stack<>();
//
//
//
//    public VariableVisitor() {
//    }
//
//    @Override
//    public String visitVardecl(@NotNull PoCoParser.VardeclContext ctx) {
//        Variable var = new Variable(ctx.id().getText());
//        variableBox.AddVar(var);
//        return super.visitVardecl(ctx);
//    }
//
//    @Override
//    public String visitMacrodecl(@NotNull PoCoParser.MacrodeclContext ctx) {
//        currentVariable = new Variable(ctx.id().getText());
//        partCollectors.push(currentVariable);
//        visitChildren(ctx);
//        variableBox.AddVar(currentVariable);
//        currentVariable = null;
//        partCollectors.pop();
//        return null;
//    }
//
//    @Override
//    public String visitIdlist(@NotNull PoCoParser.IdlistContext ctx) {
//        visitChildren(ctx);
//        currentVariable.AddParameter(ctx.id().getText());
//        return null;
//    }
//
//    VariablePart parseVarRef(@NotNull PoCoParser.ReContext ctx) {
//        currentParts.push(new VariablePart(ctx.qid().getText(), true));
//        partCollectors.push(currentParts.peek());
//        if (ctx.opparamlist() != null) {
//            visitOpparamlist(ctx.opparamlist());
//        }
//        VariablePart toReturn = currentParts.pop();
//        partCollectors.pop();
//        return toReturn;
//    }
//
//    @Override
//    public String visitRe(@NotNull PoCoParser.ReContext ctx) {
//        if (currentVariable == null) {
//            return null;
//        }
//
//        if (ctx.DOLLAR() != null) {
//            partCollectors.peek().AddVariablePart(parseVarRef(ctx));
//            return null;
//        }
//
//        StringBuilder builder = new StringBuilder();
//        for (ParseTree tree : ctx.children) {
//            if (tree instanceof  TerminalNode || tree instanceof PoCoParser.RebopContext || tree instanceof PoCoParser.ReuopContext) {
//                builder.append(tree.getText());
//            }
//
//            if (builder.length() > 0) {
//                partCollectors.peek().AddVariablePart(new VariablePart(builder.toString(), false));
//                builder = new StringBuilder();
//            }
//
//            visit(tree);
//        }
//        if (builder.length() > 0) {
//            partCollectors.peek().AddVariablePart(new VariablePart(builder.toString(), false));
//        }
//
//        return null;
//    }
//
//
//    @Override
//    public String visitFunction(@NotNull PoCoParser.FunctionContext ctx) {
//        if (currentVariable == null) {
//            return null;
//        }
//
//        StringBuilder builder = new StringBuilder();
//        for (ParseTree tree : ctx.children) {
//            if (tree instanceof PoCoParser.ArglistContext) {
//                if (builder.length() > 0) {
//                    partCollectors.peek().AddVariablePart(new VariablePart(builder.toString(), false));
//                    builder = new StringBuilder();
//                }
//                visit(tree);
//            } else {
//                builder.append(tree.getText());
//            }
//        }
//
//        if (builder.length() > 0) {
//            partCollectors.peek().AddVariablePart(new VariablePart(builder.toString(), false));
//        }
//
//        return null;
//    }
}
