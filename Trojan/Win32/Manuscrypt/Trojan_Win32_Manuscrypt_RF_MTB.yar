
rule Trojan_Win32_Manuscrypt_RF_MTB{
	meta:
		description = "Trojan:Win32/Manuscrypt.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 6d 00 2f 00 bb 78 00 7a 00 be 6d 00 65 00 90 02 60 c7 44 24 90 01 01 78 00 76 00 c7 44 24 90 01 01 2e 00 79 00 89 7c 24 90 01 01 89 54 24 90 01 01 89 4c 24 90 01 01 c7 44 24 90 01 01 25 00 64 00 c7 44 24 90 01 01 2e 00 68 00 c7 44 24 90 01 01 74 00 6d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}