
rule Trojan_BAT_FormBook_NFG_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {03 74 bc 00 00 02 6f 90 01 02 00 06 0a 02 06 17 6f 90 01 02 00 06 0b 02 6f 90 01 02 00 06 0c 02 08 07 6f 90 01 02 00 06 2c 08 02 08 90 00 } //01 00 
		$a_01_1 = {41 6f 6c 6d 67 6d 63 66 74 6f 67 6c 63 72 75 67 71 62 75 72 61 61 6e 65 } //00 00  Aolmgmcftoglcrugqburaane
	condition:
		any of ($a_*)
 
}