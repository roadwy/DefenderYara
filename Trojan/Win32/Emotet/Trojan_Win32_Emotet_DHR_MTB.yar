
rule Trojan_Win32_Emotet_DHR_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 45 f9 8a 4d f8 8a 55 f9 c0 e8 04 c0 e1 02 0a c1 8a 4d fa 88 06 8a c1 c0 e8 02 c0 e2 04 0a c2 46 c0 e1 06 0a 4d fb 88 06 46 88 0e } //1
		$a_01_1 = {6a 40 68 00 10 00 00 ff 75 0c 56 ff 55 c0 ff 75 0c 8b f8 ff 75 08 57 ff 55 e0 83 c4 0c ff 75 0c 8d 45 0c 50 57 56 53 56 ff 75 f4 ff 55 e4 f7 d8 1b c0 23 c7 } //1
		$a_01_2 = {57 57 57 57 ff d6 57 57 57 57 ff d6 57 57 57 57 ff d6 57 57 57 57 ff d6 57 57 57 57 ff d6 57 57 57 57 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}