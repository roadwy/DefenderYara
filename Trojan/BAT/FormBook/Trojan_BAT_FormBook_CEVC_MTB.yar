
rule Trojan_BAT_FormBook_CEVC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.CEVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 16 74 00 00 0c 2b 16 20 a4 d5 a6 6c 28 90 01 03 06 07 08 28 90 01 03 06 0b 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d df 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}