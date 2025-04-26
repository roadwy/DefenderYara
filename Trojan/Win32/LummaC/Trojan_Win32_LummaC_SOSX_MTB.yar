
rule Trojan_Win32_LummaC_SOSX_MTB{
	meta:
		description = "Trojan:Win32/LummaC.SOSX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 0c b9 ?? ?? ?? ?? 89 44 24 28 8b 44 24 28 3d ?? ?? ?? ?? b8 ?? ?? ?? ?? 0f 4c c1 3d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}