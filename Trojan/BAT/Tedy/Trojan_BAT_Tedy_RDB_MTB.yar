
rule Trojan_BAT_Tedy_RDB_MTB{
	meta:
		description = "Trojan:BAT/Tedy.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {25 16 6f 13 00 00 0a 25 17 6f 14 00 00 0a 25 17 6f 15 00 00 0a 25 17 6f 16 00 00 0a 0b } //00 00 
	condition:
		any of ($a_*)
 
}