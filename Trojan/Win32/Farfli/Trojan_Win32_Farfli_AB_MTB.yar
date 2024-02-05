
rule Trojan_Win32_Farfli_AB_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 74 24 0c 80 c2 21 85 f6 76 10 8b 44 24 08 8a 08 32 ca 02 ca 88 08 40 4e 75 f4 } //01 00 
		$a_01_1 = {8b 0b 8b 73 04 8b 7c 24 18 8b d1 03 f7 8b f8 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 89 43 f8 8b 4c 24 20 8b 44 24 10 40 83 c3 28 8b 11 33 c9 89 44 24 10 66 8b 4a 06 3b c1 0f 8c } //00 00 
	condition:
		any of ($a_*)
 
}