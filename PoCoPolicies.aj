package com.poco.demo;

import java.lang.reflect.Method;
import java.lang.reflect.Constructor;

import com.poco.event.Action;
import com.poco.event.Result;
import com.poco.policy.PoCo;
import com.poco.policy.RootPolicy;
import com.poco.policy.examplePolicies.*;
import com.poco.sre.SRE;

public aspect PoCoPolicies {
    private RootPolicy root = new RootPolicy();

    public PoCoPolicies() {
    }

    pointcut PC4Reflection():
        call (* Method.invoke(Object, Object...)) && !within(com.poco.runtime.*);

    Object around(): PC4Reflection()   { 
        return new SRE(null, Action.AnyAction); 
    }

    pointcut PointCut0():
        call(java.net.ServerSocket.new(int)) || 
		call(java.net.Socket.new(java.net.InetAddress,int,..)) || 
		call(java.io.RandomAccessFile.new(File, String)) || 
		call(* java.net.DatagramSocket.send(java.net.DatagramPacket)) || 
		call(* javax.mail.Transport.send(javax.mail.Message,*)) || 
		call(* java.net.MulticastSocket.leaveGroup(java.net.InetAddress)) || 
		call(* javax.mail.Transport.send(javax.mail.Message)) || 
		call(java.net.Socket.new(java.lang.String,int,..)) || 
		call(* com.sun.mail.smtp.SMTPTransport.sendMessage(javax.mail.Message,*)) || 
		call(* java.lang.Runtime.exec(*)) || 
		call(java.lang.ClassLoader+.new()) || 
		call(* com.sun.mail.imap.IMAPStore.protocolConnect(java.lang.String,int,..)) || 
		call(java.io.FileInputStream.new(File)) || 
		call(java.util.zip.ZipFile.new(String)) || 
		call(* javax.mail.Service.protocolConnect(java.lang.String,int, ..)) || 
		call(* java.net.MulticastSocket.send(java.net.DatagramPacket,..)) || 
		call(java.io.FileWriter.new(File)) || 
		call(java.io.FileInputStream.new(String)) || 
		call(* com.sun.mail.pop3.POP3Store.protocolConnect(java.lang.String,int,..)) || 
		call(java.io.RandomAccessFile.new(String, String)) || 
		call(* com.sun.mail.smtp.SMTPTransport.protocolConnect(java.lang.String,int,..)) || 
		call(* java.net.MulticastSocket.joinGroup(java.net.InetAddress)) && !within(com.poco.runtime.*);

    Object around(): PointCut0() {
        root.query(new Action(thisJoinPoint));
        if(root.hasRes4Action())
            return root.getRes4Action();
        else
            return proceed();
    }

    pointcut PointCut1(Method run):
        target(run) &&call(Object Method.invoke(..));

    Object around(Method run): PointCut1(run) {
        Object ret = proceed(run);
        Result promRes = new Result(run).setRes(ret);
        root.query(promRes);
        return promRes.getEvtRes();
    }

    pointcut PointCut2(Constructor run):
        target(run) && call(* Constructor.newInstance(..));

    Object around(Constructor run): PointCut2(run) {
        Object ret = proceed(run);
        Result promRes = new Result(run).setRes(ret);
        root.query(promRes);
        return promRes.getEvtRes();
    }

}
