
rule Trojan_Win32_DeapaxCrypt_RD_MTB{
	meta:
		description = "Trojan:Win32/DeapaxCrypt.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 ea cc 34 00 00 89 55 90 02 05 8b 45 90 02 05 33 90 02 07 89 45 90 02 05 8b 4d 90 02 05 8b 95 90 01 04 8b 45 90 02 05 89 04 8a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}