
rule Trojan_Win32_LummaC_MAT_MTB{
	meta:
		description = "Trojan:Win32/LummaC.MAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 74 24 30 8b 0c 87 0f b6 04 06 6a 03 30 81 } //1
		$a_03_1 = {45 89 6c 24 14 81 fd ?? ?? ?? ?? 7d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}