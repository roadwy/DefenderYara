
rule Trojan_Win32_Emotet_DL{
	meta:
		description = "Trojan:Win32/Emotet.DL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 45 53 54 41 50 50 2e 45 58 45 } //1 TESTAPP.EXE
		$a_01_1 = {65 72 65 72 59 23 57 24 48 65 72 68 77 65 48 65 72 2e 70 64 62 } //1 ererY#W$HerhweHer.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}