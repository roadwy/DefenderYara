
rule Trojan_BAT_Tedy_ATY_MTB{
	meta:
		description = "Trojan:BAT/Tedy.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 6f 90 01 03 0a 06 72 1f 00 00 70 6f 90 01 03 0a 06 17 6f 90 01 03 0a 06 17 6f 90 01 03 0a 06 16 6f 90 01 03 0a 06 17 6f 90 01 03 0a 73 16 00 00 0a 25 06 90 00 } //01 00 
		$a_01_1 = {64 65 66 65 6e 64 65 72 20 69 73 6b 6c } //00 00 
	condition:
		any of ($a_*)
 
}