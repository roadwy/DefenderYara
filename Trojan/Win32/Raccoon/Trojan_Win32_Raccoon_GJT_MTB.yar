
rule Trojan_Win32_Raccoon_GJT_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 94 15 ?? ?? ?? ?? 8b 45 10 03 45 f0 0f b6 08 33 ca 8b 55 10 03 55 f0 88 0a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}