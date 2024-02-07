
rule Trojan_BAT_SnakeKeylogger_EC_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {24 37 31 36 63 30 64 61 39 2d 31 35 31 65 2d 34 66 36 32 2d 38 31 39 66 2d 62 31 34 30 65 65 65 31 66 62 66 38 } //01 00  $716c0da9-151e-4f62-819f-b140eee1fbf8
		$a_81_1 = {4e 61 74 69 6f 6e 61 6c 20 53 68 69 72 74 20 53 68 6f 70 } //01 00  National Shirt Shop
		$a_81_2 = {43 6f 6e 67 72 61 74 75 6c 61 74 69 6f 6e 73 21 20 59 6f 75 20 77 6f 6e } //01 00  Congratulations! You won
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_4 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}