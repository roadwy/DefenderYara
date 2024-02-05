
rule HackTool_Linux_AirCrack_B_MTB{
	meta:
		description = "HackTool:Linux/AirCrack.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {83 e8 01 0f 85 87 fe ff ff 48 8d 90 01 03 01 00 e8 5d cc ff ff 48 8b 90 01 03 0b 00 e8 90 01 04 4c 89 ea 4c 89 e6 48 89 c5 48 89 c7 e8 90 01 03 00 48 89 ef e8 90 01 03 00 48 8b 54 24 50 4c 8d 90 01 03 01 00 41 b8 90 01 02 00 00 48 85 d2 0f 84 90 01 03 ff 48 8b 90 01 03 0b 00 48 8d b2 00 01 00 00 c7 82 68 01 00 00 01 00 00 00 e8 90 01 03 00 e9 90 01 02 ff ff 90 00 } //02 00 
		$a_03_1 = {41 b8 01 00 00 00 4c 89 f1 4c 89 ea 48 89 ee e8 90 01 03 00 85 c0 74 90 01 01 48 8b bb 08 03 00 00 48 83 83 50 01 00 00 01 48 85 ff 75 90 01 01 e8 62 90 01 03 48 89 83 08 03 00 00 48 89 c7 48 85 c0 0f 85 90 01 03 ff 48 8d 90 01 04 00 e8 90 01 03 ff e9 90 01 03 ff 66 0f 1f 44 00 00 e8 90 01 03 00 48 89 83 00 03 00 00 48 89 c7 48 85 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}