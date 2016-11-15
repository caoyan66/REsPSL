package com.pocoDesktop;

import java.awt.Component;
import java.io.File;

import javax.swing.DefaultListCellRenderer;
import javax.swing.JList;

public class FileRenderer extends DefaultListCellRenderer {

    public FileRenderer() {

    }

    @Override
    public Component getListCellRendererComponent(JList<? extends Object> list,
                                                  Object value, int index, boolean isSelected, boolean cellHasFocus) {
        if(value instanceof File) {
            File f = (File) value;

            setText(f.getName());
            setToolTipText(f.getPath());

            if(isSelected) {
                setBackground(list.getSelectionBackground());
                setForeground(list.getSelectionForeground());
            } else {
                setBackground(list.getBackground());
                setForeground(list.getForeground());
            }
        }

        return this;
    }

}