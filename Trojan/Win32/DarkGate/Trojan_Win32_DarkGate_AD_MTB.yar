
rule Trojan_Win32_DarkGate_AD_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {8b 44 24 04 [0-10] 8b d7 32 54 1d ff f6 d2 88 54 18 ff 43 4e 90 13 [0-30] 8b 44 24 04 } //100
		$a_03_2 = {8b 44 24 04 [0-10] 8b 14 24 8a 54 32 ff 8a 4c 1d ff 32 d1 88 54 30 ff 8b c5 [0-10] 3b d8 7d 03 43 eb 05 bb 01 00 00 00 46 4f 90 13 8b 44 24 04 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100+(#a_03_2  & 1)*100) >=101
 
}