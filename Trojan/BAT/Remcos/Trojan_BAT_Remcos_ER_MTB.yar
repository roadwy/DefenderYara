
rule Trojan_BAT_Remcos_ER_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {07 11 04 03 11 04 91 04 11 04 04 8e 69 5d 91 61 08 11 04 08 8e 69 5d 91 61 9c 11 04 17 d6 13 04 11 04 09 31 db } //01 00 
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_81_2 = {41 63 74 69 76 61 74 6f 72 } //01 00 
		$a_81_3 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //00 00 
	condition:
		any of ($a_*)
 
}