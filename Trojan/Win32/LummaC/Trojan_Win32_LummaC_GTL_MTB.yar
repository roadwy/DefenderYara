
rule Trojan_Win32_LummaC_GTL_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GTL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cb c1 e1 ?? 03 4d ?? 8d 14 18 33 ca 33 4d ?? 05 ?? ?? ?? ?? 2b f9 83 6d ?? ?? 89 7d ?? 89 45 ?? 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}