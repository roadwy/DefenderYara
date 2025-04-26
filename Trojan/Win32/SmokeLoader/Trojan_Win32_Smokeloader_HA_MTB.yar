
rule Trojan_Win32_Smokeloader_HA_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.HA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b ec 51 c7 45 fc 02 00 00 00 8b 45 0c 01 45 fc 83 6d fc 02 8b 45 08 8b 4d 0c 31 08 c9 c2 08 00 55 8b ec 8b 4d 08 } //10
		$a_03_1 = {8b ca c1 e9 ?? 03 4d e4 89 45 08 33 c8 89 4d f4 8b 45 f4 01 05 ?? ?? ?? ?? 8b 45 f4 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}