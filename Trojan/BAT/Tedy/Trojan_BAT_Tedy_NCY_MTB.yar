
rule Trojan_BAT_Tedy_NCY_MTB{
	meta:
		description = "Trojan:BAT/Tedy.NCY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {73 15 00 00 0a 0d 08 19 18 73 90 01 03 0a 0a 09 07 16 07 8e 69 6f 90 01 03 0a 00 06 09 6f 90 01 03 0a 16 09 6f 90 01 03 0a 8e 69 6f 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {46 72 65 65 57 61 79 50 68 61 6e 74 6f 6d } //00 00  FreeWayPhantom
	condition:
		any of ($a_*)
 
}