
rule Trojan_BAT_Tedy_NEAC_MTB{
	meta:
		description = "Trojan:BAT/Tedy.NEAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {00 fe 0c 00 00 20 01 00 00 00 fe 01 39 24 00 00 00 00 28 33 00 00 0a 72 37 05 00 70 28 34 00 00 0a 6f 35 00 00 0a 28 40 00 00 0a 26 } //05 00 
		$a_01_1 = {61 00 48 00 52 00 30 00 63 00 48 00 4d 00 36 00 4c 00 79 00 39 00 30 00 4c 00 6d 00 31 00 6c 00 4c 00 31 00 4a 00 6c 00 63 00 6e 00 56 00 73 00 62 00 47 00 38 00 3d 00 } //00 00  aHR0cHM6Ly90Lm1lL1JlcnVsbG8=
	condition:
		any of ($a_*)
 
}