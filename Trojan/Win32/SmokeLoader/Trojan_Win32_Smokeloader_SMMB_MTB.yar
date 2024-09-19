
rule Trojan_Win32_Smokeloader_SMMB_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 6c 8b 45 6c 31 4d 74 03 c3 33 45 74 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 2b f0 83 3d ?? ?? ?? ?? 0c 89 45 6c 75 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}