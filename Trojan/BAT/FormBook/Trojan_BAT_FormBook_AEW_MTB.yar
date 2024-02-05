
rule Trojan_BAT_FormBook_AEW_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0c 16 13 06 2b 17 00 08 11 06 07 11 06 9a 1f 10 28 90 01 03 0a 9c 00 11 06 17 58 13 06 11 06 07 8e 69 fe 04 13 07 11 07 2d dc 90 00 } //01 00 
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 36 00 } //00 00 
	condition:
		any of ($a_*)
 
}