
rule TrojanSpy_BAT_VB_D{
	meta:
		description = "TrojanSpy:BAT/VB.D,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 72 00 65 00 70 00 6f 00 72 00 74 00 73 00 20 00 66 00 72 00 6f 00 6d 00 3a 00 20 00 } //1 Keylogger reports from: 
		$a_01_1 = {4b 65 79 53 74 75 62 5c 4b 65 79 53 74 75 62 5c 6f 62 6a 5c 44 65 62 75 67 5c 4b 65 79 53 74 75 62 2e 70 64 62 } //2 KeyStub\KeyStub\obj\Debug\KeyStub.pdb
		$a_01_2 = {4b 65 79 53 74 75 62 2e 65 78 65 } //1 KeyStub.exe
		$a_00_3 = {5c 00 77 00 61 00 75 00 64 00 69 00 6f 00 33 00 32 00 2e 00 78 00 6d 00 6c 00 } //2 \waudio32.xml
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_00_3  & 1)*2) >=4
 
}