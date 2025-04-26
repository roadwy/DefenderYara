
rule Worm_Win32_Notube_A{
	meta:
		description = "Worm:Win32/Notube.A,SIGNATURE_TYPE_PEHSTR,0c 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {e8 00 f4 00 f4 00 f0 00 ba 00 af 00 af 00 f7 00 f7 00 f7 00 ae 00 f9 00 ef 00 f5 00 f4 00 f5 00 e2 00 e5 00 ae 00 e3 00 ef 00 ed 00 af 00 f6 00 af 00 eb 00 } //10
		$a_01_1 = {41 00 44 00 3a 00 5c 00 62 00 61 00 69 00 78 00 61 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //1 AD:\baixa\Project1.vbp
		$a_01_2 = {4d 00 65 00 73 00 73 00 65 00 6e 00 67 00 65 00 72 00 5c 00 6d 00 73 00 67 00 73 00 63 00 2e 00 64 00 6c 00 6c 00 } //1 Messenger\msgsc.dll
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=10
 
}