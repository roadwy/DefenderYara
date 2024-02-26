
rule Trojan_BAT_FormBook_ABSG_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABSG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {0c 08 07 6f 90 01 01 00 00 0a 16 73 90 01 01 00 00 0a 0d 06 8e 69 8d 90 01 01 00 00 01 13 04 09 11 04 16 11 04 8e 69 6f 90 01 01 00 00 0a 26 11 04 28 90 01 01 00 00 06 26 73 90 01 01 00 00 06 17 6f 90 01 01 00 00 06 de 14 09 2c 06 09 6f 90 01 01 00 00 0a dc 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}