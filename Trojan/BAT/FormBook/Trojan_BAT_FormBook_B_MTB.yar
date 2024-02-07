
rule Trojan_BAT_FormBook_B_MTB{
	meta:
		description = "Trojan:BAT/FormBook.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 16 1f 4c 9d 25 17 1f 6f 9d 25 18 1f 61 9d 25 19 1f 64 9d 2a } //01 00 
		$a_00_1 = {62 65 2d 72 75 6e 2d 69 6e 20 51 4f 53 20 7a 6f 64 65 } //00 00  be-run-in QOS zode
	condition:
		any of ($a_*)
 
}