
rule Trojan_Win32_Smokeloader_MEE_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.MEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e8 05 89 45 fc 8b 45 dc 01 45 fc 8b 4d f8 03 4d f0 c1 e3 04 03 5d d8 33 d9 81 3d ?? ?? ?? ?? 03 0b 00 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}