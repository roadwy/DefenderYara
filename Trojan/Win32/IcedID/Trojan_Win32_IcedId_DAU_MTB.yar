
rule Trojan_Win32_IcedId_DAU_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {53 6a 01 53 53 8d 44 24 90 01 01 50 89 5c 24 90 01 01 ff 15 90 01 04 85 c0 75 90 01 01 6a 08 6a 01 53 53 8d 4c 24 90 1b 00 51 ff 15 90 1b 02 85 c0 90 00 } //01 00 
		$a_81_1 = {6a 7a 61 57 6d 76 55 34 4e 78 77 68 4f 58 51 } //00 00  jzaWmvU4NxwhOXQ
	condition:
		any of ($a_*)
 
}