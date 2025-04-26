
rule Trojan_WinNT_Omexo_A{
	meta:
		description = "Trojan:WinNT/Omexo.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {80 3e b8 75 05 8b 46 01 eb 03 83 c8 ff } //1
		$a_01_1 = {b9 90 90 90 00 03 ce 0f c9 8b 74 24 10 f0 0f c7 0e } //1
		$a_01_2 = {c7 03 50 55 54 41 } //2
		$a_01_3 = {74 0a 8d 72 34 b9 02 00 00 00 f3 a5 89 d7 68 90 7d 33 50 e8 6a 00 00 00 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*3) >=3
 
}