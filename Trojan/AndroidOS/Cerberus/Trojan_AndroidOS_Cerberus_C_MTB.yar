
rule Trojan_AndroidOS_Cerberus_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Cerberus.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {12 02 35 12 90 01 02 48 05 03 02 14 08 90 01 02 05 00 90 01 02 04 08 dc 08 02 01 48 08 09 08 d3 4b e5 7d b0 ab da 0c 0b 00 b3 ac b0 0c b0 5c 93 05 04 04 d8 05 05 ff b0 5c b4 44 b0 4c 97 04 0c 08 8d 44 4f 04 06 02 14 04 0a d1 00 00 14 05 90 01 02 09 00 b3 a4 b1 4b 90 01 02 0b 05 d8 02 02 01 28 d3 13 00 1c 00 35 07 90 01 02 93 00 0a 04 d8 07 07 01 28 f8 22 00 90 01 02 70 20 90 01 02 60 00 11 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}