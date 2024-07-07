
rule HackTool_BAT_PassViewer_A{
	meta:
		description = "HackTool:BAT/PassViewer.A,SIGNATURE_TYPE_PEHSTR,04 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6f 63 74 6f 72 70 6f 6c 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 Doctorpol.My.Resources
		$a_01_1 = {44 6f 45 76 69 6c 57 6f 72 6b } //1 DoEvilWork
		$a_01_2 = {44 6f 63 74 6f 72 70 6f 6c 2e 65 78 65 } //1 Doctorpol.exe
		$a_01_3 = {44 65 62 75 67 5c 44 6f 63 74 6f 72 70 6f 6c 2e 70 64 62 } //1 Debug\Doctorpol.pdb
		$a_01_4 = {44 00 6f 00 63 00 74 00 6f 00 72 00 70 00 6f 00 6c 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Doctorpol.Resources
		$a_01_5 = {54 00 56 00 71 00 51 00 } //1 TVqQ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}