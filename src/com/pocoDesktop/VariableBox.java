package com.pocoDesktop;

import java.util.LinkedHashMap;

/**
 * Lightweight container of Variable objects. Represents the policy-level
 * scope of variables for lookup.
 */
public class VariableBox {

    public LinkedHashMap<String, Variable> box;

    public VariableBox() {
        box = new LinkedHashMap<>();
    }

    public boolean IsVarType(String varName) {
        return box.get(varName).isVarType();
    }

    public boolean Contains(String varName) {
        return box.containsKey(varName);
    }

    public Variable GetVar(String varname) {
        return box.get(varname);
    }

    public void AddVar(Variable var) {
        box.put(var.getName(), var);
    }
}
