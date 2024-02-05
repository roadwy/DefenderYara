
rule Trojan_BAT_LockScreen_ALX_MTB{
	meta:
		description = "Trojan:BAT/LockScreen.ALX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 7e 1f 00 00 0a 72 33 00 00 70 6f 20 00 00 0a 0a 06 72 a7 00 00 70 6f 23 00 00 0a 14 fe 01 0b 07 2c 11 06 72 a7 00 00 70 72 c5 00 00 70 6f 24 00 00 0a 00 2a } //01 00 
		$a_81_1 = {6e 69 61 73 6f 6c 61 74 72 69 6b 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //01 00 
		$a_81_2 = {31 41 4b 35 75 70 4e 79 65 39 65 76 76 48 74 47 45 39 4c 53 36 6a 68 39 56 54 4c 41 79 48 63 74 6b 6e } //01 00 
		$a_81_3 = {43 6f 6d 70 75 74 65 72 5f 55 6e 6c 6f 63 6b 65 64 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}