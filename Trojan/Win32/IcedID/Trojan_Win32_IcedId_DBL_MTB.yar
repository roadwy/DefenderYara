
rule Trojan_Win32_IcedId_DBL_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {53 6a 01 53 53 8d 44 24 90 01 01 50 ff 15 90 01 04 85 c0 75 48 6a 08 6a 01 53 53 8d 4c 24 90 1b 00 51 ff 15 90 1b 01 85 c0 90 00 } //01 00 
		$a_81_1 = {45 63 58 31 45 73 41 64 75 5a 70 4a 72 51 47 6e 73 47 72 48 6c 32 50 73 44 4b 35 62 58 52 31 30 66 36 59 6d 75 43 75 30 6e 41 55 63 61 37 36 4d 67 70 4e } //00 00  EcX1EsAduZpJrQGnsGrHl2PsDK5bXR10f6YmuCu0nAUca76MgpN
	condition:
		any of ($a_*)
 
}