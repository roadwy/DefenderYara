
rule Trojan_Win32_CryptInject_PU_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {35 15 05 00 00 74 90 01 01 83 3d 90 01 04 00 8b 55 0c 8b 4d f8 8b 04 8a 8b 55 14 8b 4d fc 33 04 8a 8b 55 08 8b 4d f8 89 04 8a 83 3d 90 01 04 00 74 90 01 01 83 3d 90 01 04 00 74 90 01 01 c7 05 90 01 04 93 0c 00 00 83 3d 90 01 04 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}