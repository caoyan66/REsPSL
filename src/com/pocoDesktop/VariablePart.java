package com.pocoDesktop;

import java.util.ArrayList;
import java.util.List;

/**
 * Part of a Variable. A series of VariableParts combine to form
 * the contents of a single variable. A VariablePart can either be
 * pure text or a reference to another variable(or argument).
 */
public class VariablePart implements IVarPartCollection {
    private String _textPart;
    private String _refersTo;
    private ArrayList<VariablePart> args;

    public VariablePart(String text, boolean reference) {
        args = new ArrayList<>();
        if (reference) {
            this._refersTo = text;
        } else {
            this._textPart = text;
        }
    }

    public String GetTextPart() {
        return _textPart;
    }

    public String GetReference() { return _refersTo; }

    public boolean IsReference() {
        return _refersTo != null;
    }

    public List<VariablePart> GetArguments() {
        return args;
    }

    /**
     * Adds a VariablePart to the arguments list for this variable reference
     * @param part argument to add
     * @return
     */
    public boolean AddVariablePart(VariablePart part) {
        return args.add(part);
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        if (IsReference()) {
            builder.append("$");
            builder.append(_refersTo);
            builder.append("(");

            for (int i = 0; i < args.size(); i++) {
                builder.append(args.get(i).toString());
                if (i != args.size() - 1) {
                    builder.append(", ");
                }
            }

            builder.append(")");
        } else {
            builder.append(_textPart);
        }

        return builder.toString();
    }
}
