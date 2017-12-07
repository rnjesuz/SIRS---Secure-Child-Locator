JFLAGS =
JC = javac
.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = \
        ServerThread.java \
        Server.java \
		Client.java \
		App.java \
		Beacon.java \
		PuppetMaster.java
		
default: classes

classes: $(CLASSES:.java=.class)

clean:
	$(RM) *.class