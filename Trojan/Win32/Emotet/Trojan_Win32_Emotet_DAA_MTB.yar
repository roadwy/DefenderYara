
rule Trojan_Win32_Emotet_DAA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c6 2b c2 d1 e8 03 c2 8b 54 24 14 c1 e8 05 6b c0 23 8b ce 2b c8 8a 04 4a 30 04 1e } //1
		$a_01_1 = {8d 0c 07 33 d2 6a 23 8b c7 5b f7 f3 8b 44 24 10 8a 04 50 30 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}