
rule Trojan_BAT_Fareit_SG_MTB{
	meta:
		description = "Trojan:BAT/Fareit.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 08 06 8e 69 5d 06 08 06 8e 69 5d 91 07 08 07 8e 69 5d 91 61 06 08 17 58 06 8e 69 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 08 15 58 0c 08 16 2f cb } //01 00 
		$a_01_1 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //01 00  Form1_Load
		$a_01_2 = {67 65 74 5f 43 75 6c 74 75 72 65 } //00 00  get_Culture
	condition:
		any of ($a_*)
 
}