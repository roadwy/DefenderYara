
rule Adware_MacOS_Ketin_C_MTB{
	meta:
		description = "Adware:MacOS/Ketin.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 8d 05 39 42 02 00 31 c9 48 8b 15 18 3c 02 00 8b 7d e4 48 8b 12 48 89 c6 e8 e4 a2 01 00 48 89 45 d8 48 83 7d d8 00 } //01 00 
		$a_00_1 = {48 89 c1 48 8d 15 08 63 04 00 31 f6 41 b8 81 00 00 00 48 8b bd d0 fe ff ff 40 88 b5 8f fe ff ff 44 89 c6 4c 8b 8d a8 fe ff ff 48 89 8d 80 fe ff ff 4c 89 c9 49 89 c0 8a 85 8f fe ff ff } //01 00 
		$a_00_2 = {73 65 6e 64 45 76 65 6e 74 3a 68 6f 73 74 4e 61 6d 65 3a 67 30 62 74 49 50 72 31 3a 63 61 6c 6c 62 61 63 6b } //00 00  sendEvent:hostName:g0btIPr1:callback
	condition:
		any of ($a_*)
 
}