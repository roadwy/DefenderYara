
rule Trojan_BAT_FormBook_MBGQ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 16 0a 2b 19 07 06 08 06 18 5a 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a d2 9c 06 17 58 0a 06 07 8e 69 fe 04 13 05 11 05 2d db 90 00 } //01 00 
		$a_01_1 = {51 55 41 4e 4c 59 44 41 49 4c 59 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}