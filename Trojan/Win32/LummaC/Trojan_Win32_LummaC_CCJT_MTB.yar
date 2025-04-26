
rule Trojan_Win32_LummaC_CCJT_MTB{
	meta:
		description = "Trojan:Win32/LummaC.CCJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 94 c6 0f 44 c3 83 3d ?? ?? ?? ?? ?? 0f 9c c2 0f 4d c6 89 fe 30 f2 0f 45 c3 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}