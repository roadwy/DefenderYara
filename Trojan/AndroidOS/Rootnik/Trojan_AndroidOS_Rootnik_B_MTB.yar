
rule Trojan_AndroidOS_Rootnik_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Rootnik.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6c 6f 63 6b 4f 70 65 72 61 74 69 6f 6e 00 28 4c 90 01 01 61 76 61 90 00 } //01 00 
		$a_03_1 = {72 74 73 65 72 76 69 63 65 20 2d 2d 75 73 65 72 20 30 20 2d 61 90 01 02 73 00 61 6d 20 73 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}