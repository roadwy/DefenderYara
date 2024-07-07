
rule Trojan_Win32_Smokeloader_RP_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 0c 69 c9 90 01 04 81 c1 90 01 04 89 0d 90 01 04 8a 15 90 01 04 30 14 30 83 ff 0f 75 90 00 } //1
		$a_01_1 = {78 6f 68 65 6c 6f 63 61 6a 61 78 65 6b 65 68 61 76 65 } //1 xohelocajaxekehave
		$a_01_2 = {66 69 70 65 6c 69 64 69 76 75 6b 61 6c 75 76 69 6a 61 68 65 76 61 76 75 7a 75 6b 65 } //1 fipelidivukaluvijahevavuzuke
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}