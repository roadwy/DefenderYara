
rule Trojan_Win32_LummaC_MZT_MTB{
	meta:
		description = "Trojan:Win32/LummaC.MZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 34 ?? 03 c2 0f b6 c0 0f b6 44 04 ?? 30 83 ?? ?? ?? ?? 43 81 fb ?? ?? ?? ?? 7c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}