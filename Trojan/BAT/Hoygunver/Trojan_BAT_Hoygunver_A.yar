
rule Trojan_BAT_Hoygunver_A{
	meta:
		description = "Trojan:BAT/Hoygunver.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 00 66 69 6c 65 32 00 4d 61 69 6e 00 72 75 6e 00 67 6f 00 68 65 79 00 } //01 00 
		$a_01_1 = {5c 00 52 00 75 00 6e 00 00 07 4d 00 53 00 45 00 } //01 00  \Run܀MSE
		$a_01_2 = {5c 00 52 00 75 00 6e 00 00 29 4d 00 69 00 63 00 } //01 00  \Run⤀Mic
		$a_01_3 = {28 09 00 00 0a 2d 27 7e 01 00 00 04 28 0a 00 00 0a 2d 1b 7e 02 00 00 04 28 0a 00 00 0a 2c 0f 7e 02 00 00 04 7e 01 00 00 04 28 0b 00 00 0a 7e 0c 00 00 0a 72 01 00 00 70 17 6f 0d 00 00 0a 72 5d 00 00 70 } //00 00 
	condition:
		any of ($a_*)
 
}