
rule Trojan_Win32_Formbook_MBAR_MTB{
	meta:
		description = "Trojan:Win32/Formbook.MBAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f0 3b 4d e0 73 27 8b 45 f0 99 b9 0c 00 00 00 f7 f9 8b 45 e4 0f b6 0c 10 8b 55 dc 03 55 f0 0f b6 02 33 c1 8b 4d dc 03 4d f0 88 01 } //1
		$a_01_1 = {83 c4 0c 6a 40 68 00 30 00 00 8b 55 e0 52 6a 00 ff 15 88 60 41 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}