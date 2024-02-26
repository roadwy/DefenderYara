
rule Trojan_BAT_FormBook_ABHU_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {a2 25 17 20 90 01 03 14 28 90 01 03 06 a2 14 14 14 28 90 01 03 0a 14 20 90 01 03 14 28 90 01 03 06 18 8d 90 01 03 01 25 16 20 90 01 03 14 28 90 01 03 06 a2 25 17 20 90 01 03 14 28 90 01 03 06 a2 14 14 14 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0b 07 28 90 01 03 06 28 90 01 03 0a 0c 14 90 00 } //01 00 
		$a_01_1 = {53 6f 72 74 65 6f 51 75 69 6e 69 65 6c 61 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00  SorteoQuiniela.Resources.resources
	condition:
		any of ($a_*)
 
}