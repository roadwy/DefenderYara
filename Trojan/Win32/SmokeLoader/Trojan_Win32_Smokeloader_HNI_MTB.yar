
rule Trojan_Win32_Smokeloader_HNI_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.HNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d a4 24 00 00 00 00 8b 15 ?? ?? ?? ?? 89 54 24 10 b8 ?? ?? 00 00 01 44 24 10 8b 44 24 10 8a 0c 30 8b 15 ?? ?? ?? ?? 88 0c 32 81 3d [0-08] 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}