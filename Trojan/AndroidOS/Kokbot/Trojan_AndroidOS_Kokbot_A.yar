
rule Trojan_AndroidOS_Kokbot_A{
	meta:
		description = "Trojan:AndroidOS/Kokbot.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 43 6f 6e 74 61 63 74 73 28 29 20 31 20 6d 6f 62 69 6c 65 } //01 00 
		$a_01_1 = {75 70 4c 6f 61 64 43 6f 6e 74 61 63 74 73 28 29 20 20 43 6f 6e 74 61 63 74 73 20 6c 69 73 74 } //01 00 
		$a_01_2 = {27 2c 20 6d 65 73 73 61 67 65 50 68 6f 6e 65 3d 27 } //00 00 
	condition:
		any of ($a_*)
 
}