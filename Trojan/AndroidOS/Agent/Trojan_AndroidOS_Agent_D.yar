
rule Trojan_AndroidOS_Agent_D{
	meta:
		description = "Trojan:AndroidOS/Agent.D,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {14 04 01 2d 0c 00 b0 49 48 04 03 02 d1 95 16 07 dc 07 02 03 48 07 08 07 da 0a 09 4d b1 5a da 09 09 00 b3 a9 b0 09 b0 49 93 04 05 05 d8 04 04 ff b0 49 94 04 05 05 b0 49 97 04 09 07 8d 44 4f 04 06 02 14 04 0f ad 83 00 b3 45 d8 02 02 01 01 a9 28 d6 } //00 00 
	condition:
		any of ($a_*)
 
}