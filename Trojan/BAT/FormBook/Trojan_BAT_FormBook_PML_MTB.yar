
rule Trojan_BAT_FormBook_PML_MTB{
	meta:
		description = "Trojan:BAT/FormBook.PML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0c 07 8e 69 13 05 2b 0d 00 08 07 11 05 91 6f 90 01 03 0a 00 00 11 05 25 17 59 13 05 16 fe 02 13 06 11 06 2d e3 90 00 } //01 00 
		$a_01_1 = {50 72 6f 67 72 65 73 73 69 76 65 } //00 00 
	condition:
		any of ($a_*)
 
}