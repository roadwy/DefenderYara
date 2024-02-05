
rule Trojan_BAT_FormBook_NF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {25 26 11 0e 6a 59 69 28 90 01 03 06 25 26 13 10 20 90 01 03 00 38 90 01 03 ff 07 16 6a 28 90 01 03 06 20 90 01 03 00 38 90 01 03 ff 1b 45 90 01 07 ff 20 90 01 03 00 28 90 01 03 06 39 90 01 03 ff 26 06 28 90 01 03 06 25 26 69 13 0e 20 90 01 03 00 17 90 00 } //01 00 
		$a_01_1 = {4a 55 59 54 47 46 48 4a 4e 4b } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_NF_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {09 17 d6 0d 09 1f 10 31 08 1a 13 06 38 90 01 03 ff 1c 2b f6 07 07 d8 20 90 01 03 00 d8 17 28 90 01 03 06 28 90 01 03 0a 08 74 90 01 03 1b 07 28 90 01 03 06 90 00 } //01 00 
		$a_01_1 = {41 00 33 00 68 00 4c 00 6f 00 51 00 } //01 00 
		$a_01_2 = {57 69 6e 64 6f 77 73 41 70 70 33 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}