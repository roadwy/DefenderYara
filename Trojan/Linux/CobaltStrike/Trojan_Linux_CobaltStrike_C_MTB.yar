
rule Trojan_Linux_CobaltStrike_C_MTB{
	meta:
		description = "Trojan:Linux/CobaltStrike.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {27 86 71 8e 60 be 67 1d 41 73 25 df 04 df 68 49 da 1c 6d 38 30 81 f1 ca fc f3 07 1c 16 b0 5f 3f f6 92 46 2c 01 bd 86 93 c0 c5 66 83 } //00 00 
	condition:
		any of ($a_*)
 
}