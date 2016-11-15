package com.pocoDesktop;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a variable in the PoCo runtime.
 * A variable consists of the following parts:
 *  - Name
 *  - List of parameter names
 *  - List of parts (i.e. plain text chunks and references to other variables)
 */
public class Variable implements IVarPartCollection {
    private String _name;
    private ArrayList<VariablePart> _parts = new ArrayList<>();
    private ArrayList<String> _parameters = new ArrayList<>();

    public String getName() {
        return _name;
    }

    /**
     * Determines whether the variable is bound at runtime (i.e. is a var and not
     * a PoCo function)
     * @return true if variable bound at runtime, otherwise false
     */
    public boolean isVarType() {
        return _parts.size() == 0;
    }

    public boolean AddVariablePart(VariablePart part) {
        return _parts.add(part);
    }

    public boolean AddParameter(String parameter) {
        return _parameters.add(parameter);
    }

    public Variable(String name) {
        this._name = name;
    }

    /**
     * Converts the variable (or function) into a string using the provided arguments. All
     * references are dereferenced during the process. If any dereferencing fails (i.e. reference
     * to a variable bound at runtime), null will be returned.
     * @param box VariableBox to use for reference lookup
     * @param arguments List of argument values corresponding to this variable's parameters
     * @return Completely dereferenced string contents of variable
     */
    public String Resolve(VariableBox box, List<VariablePart> arguments) {
        if (isVarType()) {
            return null;
        }

        // Arguments to the variable could be references themselves in return
        ArrayList<String> dereferencedArguments = new ArrayList<>();
        for (VariablePart part : arguments) {
            if (!part.IsReference()) {
                dereferencedArguments.add(part.GetTextPart());
                continue;
            }

            Variable var = box.GetVar(part.GetReference());
            if (var == null) {
                return null;
            }
            String derefArg = var.Resolve(box, part.GetArguments());
            if (derefArg == null) {
                return null;
            }
            dereferencedArguments.add(derefArg);
        }

        return ResolveDereferenced(box, dereferencedArguments);
    }

    private String ResolveDereferenced(VariableBox box, List<String> derefArgs) {
        if (isVarType()) {
            return null;
        }

        StringBuilder builder = new StringBuilder();
        for (VariablePart part : _parts) {
            // Get what it is referring to
            String dereferenced = DereferenceVariable(box, part, derefArgs);
            if (dereferenced == null) {
                return null;
            }
            builder.append(dereferenced);
        }
        return builder.toString();
    }

    String DereferenceVariable(VariableBox box, VariablePart reference, List<String> arguments) {
        if (!reference.IsReference()) {
            return reference.GetTextPart();
        }

        // Is it a local variable?
        for (int i = 0; i < _parameters.size(); i++) {
            String paramName = _parameters.get(i);
            if (reference.GetReference().equals(paramName)) {
                return arguments.get(i);
            }
        }

        // Another macro or variable
        Variable var = box.GetVar(reference.GetReference());

        // Arguments to the variable could be references themselves
        ArrayList<String> dereferencedArguments = new ArrayList<>();
        for (VariablePart part : reference.GetArguments()) {
            if (part.IsReference()) {
                String derefArg = DereferenceVariable(box, part, arguments);
                if (derefArg == null) {
                    return null;
                }
                dereferencedArguments.add(derefArg);
            } else {
                dereferencedArguments.add(part.GetTextPart());
            }
        }

        return var.ResolveDereferenced(box, dereferencedArguments);
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder(_name);

        if (isVarType()) {
            builder.append(" - reference");
            return builder.toString();
        }

        builder.append("(");

        for (int i = 0; i < _parameters.size(); i++) {
            builder.append(_parameters.get(i));
            if (i != _parameters.size() - 1) {
                builder.append(", ");
            }
        }


        builder.append(") :: ");

        for (VariablePart part : _parts) {
            builder.append(part.toString());
        }

        return builder.toString();
    }
}
