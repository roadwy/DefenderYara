
rule Trojan_Win32_LummaC_BA_MTB{
	meta:
		description = "Trojan:Win32/LummaC.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 8a 84 04 ?? ?? 00 00 8b 54 24 10 8b 8c 24 ?? ?? 00 00 30 04 11 42 39 f2 0f 85 } //4
		$a_01_1 = {8b 4c 24 08 00 c1 89 4c 24 08 0f b6 c9 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}