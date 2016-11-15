package com.pocoDesktop;

import java.lang.reflect.Type;
import java.util.LinkedHashSet;

/**
 * A subclass of ASM (the Java bytecode reading library) ClassVisitor to obtain method signatures from the compiled
 * Java class.
 */
public class MethodExtractor {// extends ClassVisitor {
//    private LinkedHashSet<String> callList;
//    private String className = null;
//
//    /**
//     * Constructor. Initializes ASM API version and sets up the internal HashSet.
//     * @param setToUse external HashSet to add method signatures to.
//     */
//    public MethodExtractor(LinkedHashSet<String> setToUse) {
//        super(Opcodes.ASM5);
//        callList = setToUse;
//    }
//
//    /**
//     * Called once per Java class. Obtains the class name.
//     */
//    @Override
//    public void visit(int version, int access, String name, String signature,
//                      String superName, String[] interfaces) {
//        Type classType = Type.getObjectType(name);
//        className = classType.getClassName();
//    }
//
//    /**
//     * Called once per declared method. Generates a method signature and adds it to the HashSet.
//     */
//    @Override
//    public MethodVisitor visitMethod(int access, String name, String desc,
//                                     String signature, String[] exceptions) {
//        Type methodType = Type.getMethodType(desc);
//        Type[] argumentTypes = methodType.getArgumentTypes();
//
//        String returnType = methodType.getReturnType().getClassName();
//
//        StringBuilder args = new StringBuilder();
//        for (int i = 0; i < argumentTypes.length; i++) {
//            args.append(argumentTypes[i].getClassName());
//            if (i < argumentTypes.length - 1) {
//                args.append(", ");
//            }
//        }
//
//        StringBuilder methodSignature = new StringBuilder(returnType);
//        methodSignature.append(' ');
//        methodSignature.append(className);
//        methodSignature.append('.');
//        methodSignature.append(name);
//        methodSignature.append('(');
//        methodSignature.append(args);
//        methodSignature.append(')');
//
//        callList.add(methodSignature.toString());
//
//        return null;
//    }
}
