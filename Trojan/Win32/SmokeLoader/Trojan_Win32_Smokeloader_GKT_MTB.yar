
rule Trojan_Win32_Smokeloader_GKT_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GKT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 55 d8 8b 45 d8 3b 05 ?? ?? ?? ?? 73 ?? 0f b6 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 d8 0f b6 02 33 c1 8b 0d ?? ?? ?? ?? 03 4d d8 88 01 eb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}