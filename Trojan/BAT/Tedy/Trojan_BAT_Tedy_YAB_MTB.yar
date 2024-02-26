
rule Trojan_BAT_Tedy_YAB_MTB{
	meta:
		description = "Trojan:BAT/Tedy.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 41 56 4e 61 6d 65 } //01 00  getAVName
		$a_01_1 = {66 72 6f 6d 53 74 72 69 6e 67 54 6f 42 36 34 } //01 00  fromStringToB64
		$a_01_2 = {28 14 00 00 0a 02 6f 2c 00 00 0a 28 2d 00 00 0a 72 69 01 00 70 72 5d 01 00 70 6f 26 00 00 0a 72 fd 01 00 70 72 65 01 00 70 6f 26 00 00 0a 72 95 02 00 70 72 99 02 00 70 6f 26 00 00 0a 72 9d 02 00 70 72 a1 02 00 70 6f 26 00 00 0a } //00 00 
	condition:
		any of ($a_*)
 
}