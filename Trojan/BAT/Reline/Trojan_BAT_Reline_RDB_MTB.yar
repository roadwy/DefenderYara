
rule Trojan_BAT_Reline_RDB_MTB{
	meta:
		description = "Trojan:BAT/Reline.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 33 30 65 37 66 64 32 2d 34 39 35 35 2d 34 35 62 33 2d 39 36 64 62 2d 35 35 39 64 39 36 33 39 62 61 65 61 } //01 00 
		$a_01_1 = {5a 65 64 64 4d 65 6e 75 4c 61 75 6e 63 68 65 72 } //02 00 
		$a_01_2 = {11 2f 11 37 8f 39 00 00 01 25 4b 11 38 61 54 11 39 } //00 00 
	condition:
		any of ($a_*)
 
}