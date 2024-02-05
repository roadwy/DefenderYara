
rule TrojanSpy_Linux_XKeyLogger_A_xp{
	meta:
		description = "TrojanSpy:Linux/XKeyLogger.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {31 ed 5e 89 e1 83 e4 f8 50 54 52 68 fc 92 04 08 68 24 86 04 08 51 56 68 e0 88 04 08 } //01 00 
		$a_00_1 = {83 c4 10 83 7d 08 03 75 2d 83 c4 f4 8b 45 0c 83 c0 08 8b 10 52 8b 45 0c 83 c0 04 8b 10 52 68 66 93 04 08 6a 7f 8d 85 48 ff ff ff 50 } //00 00 
	condition:
		any of ($a_*)
 
}