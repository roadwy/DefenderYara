
rule Trojan_Win32_Emotet_PVW_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c1 b9 8f 0a 00 00 99 f7 f9 8b 84 24 90 01 04 8b 8c 24 90 01 04 8a 94 14 90 01 04 30 14 08 90 09 07 00 8a 84 14 90 00 } //01 00 
		$a_00_1 = {66 44 37 4b 54 35 78 75 61 53 6a 4d 54 43 67 4c 31 62 36 4d 66 76 67 56 43 63 67 73 31 6a 6e 52 35 42 6e } //00 00  fD7KT5xuaSjMTCgL1b6MfvgVCcgs1jnR5Bn
	condition:
		any of ($a_*)
 
}