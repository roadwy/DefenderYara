
rule Trojan_Win32_Fakemplay_A{
	meta:
		description = "Trojan:Win32/Fakemplay.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {e1 00 f6 00 e7 00 ee 00 f3 00 f8 00 ae 00 e5 00 f8 00 e5 00 00 } //1
		$a_01_1 = {e8 00 f4 00 f4 00 f0 00 ba 00 af 00 af 00 } //1
		$a_01_2 = {49 73 57 65 62 43 6f 6e 6e 65 63 74 65 64 } //1 IsWebConnected
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}