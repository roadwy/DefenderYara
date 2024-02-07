
rule Trojan_Linux_CobaltStrike_B_MTB{
	meta:
		description = "Trojan:Linux/CobaltStrike.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0a 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {6e 64 09 70 73 20 2d 61 75 78 0a 00 2f 70 3e 63 00 6f 70 65 28 ef ff ac fd 69 72 20 66 } //05 00 
		$a_00_1 = {47 65 61 63 6f 6e 2f 63 6f 72 65 2e 52 45 56 45 52 53 45 } //05 00  Geacon/core.REVERSE
		$a_00_2 = {2e 50 57 44 } //00 00  .PWD
	condition:
		any of ($a_*)
 
}