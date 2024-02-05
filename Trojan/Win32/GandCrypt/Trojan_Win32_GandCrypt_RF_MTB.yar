
rule Trojan_Win32_GandCrypt_RF_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c1 8b 0d 90 01 04 89 44 24 90 01 01 89 4c 24 90 01 01 8b 30 a1 90 01 04 89 44 24 90 01 01 a1 90 01 04 89 44 24 90 01 01 a1 90 01 04 c7 44 24 90 01 01 ba 79 37 9e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}