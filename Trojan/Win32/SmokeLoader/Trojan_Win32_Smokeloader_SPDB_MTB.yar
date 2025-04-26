
rule Trojan_Win32_Smokeloader_SPDB_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SPDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 f8 8b 45 d8 01 45 f8 8b 4d f4 03 4d ec c1 e3 04 03 5d d4 33 d9 81 3d ?? ?? ?? ?? 03 0b 00 00 75 11 56 ff 15 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}