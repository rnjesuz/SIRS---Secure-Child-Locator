JFLAGS =
JC = javac
.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = \
        ServerThread.java \
        Server.java \
		App.java \
		PuppetMaster.java
		
default: classes

classes: $(CLASSES:.java=.class)

clean:
	$(RM) *.class