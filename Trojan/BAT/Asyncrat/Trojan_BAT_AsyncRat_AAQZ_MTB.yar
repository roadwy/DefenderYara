
rule Trojan_BAT_AsyncRat_AAQZ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AAQZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {09 11 05 09 28 90 01 01 00 00 06 1e 5b 28 90 01 01 00 00 06 28 90 01 01 00 00 06 09 17 28 90 01 01 00 00 06 08 09 28 90 01 01 00 00 06 17 28 90 01 01 00 00 06 13 06 11 06 02 16 02 8e 69 28 90 01 01 00 00 06 11 06 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}