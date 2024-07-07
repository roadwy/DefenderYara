
rule Trojan_BAT_SnakeKeyLogger_RDJ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 7e 08 00 00 04 6f 25 00 00 0a 02 16 04 8e 69 6f 26 00 00 0a 0a 06 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_SnakeKeyLogger_RDJ_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7d 8a 01 00 04 06 06 7b 8a 01 00 04 28 01 00 00 2b 28 02 00 00 2b 73 b6 00 00 0a 7d 8a 01 00 04 16 06 7b 8a 01 00 04 6f b7 00 00 0a 28 b8 00 00 0a 7e 8c 01 00 04 25 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_SnakeKeyLogger_RDJ_MTB_3{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {39 34 39 35 62 30 34 61 2d 34 33 30 37 2d 34 62 61 64 2d 61 37 38 33 2d 66 39 34 31 37 32 33 35 62 62 33 38 } //1 9495b04a-4307-4bad-a783-f9417235bb38
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 4b 6c 61 73 73 } //1 WindowsFormKlass
		$a_01_2 = {53 70 61 63 65 54 65 61 6d } //1 SpaceTeam
		$a_01_3 = {41 00 78 00 76 00 68 00 4d 00 66 00 6e 00 79 00 54 00 72 00 42 00 41 00 72 00 45 00 42 00 51 00 41 00 79 00 4c 00 68 00 41 00 68 00 5a 00 42 00 4f 00 77 00 } //1 AxvhMfnyTrBArEBQAyLhAhZBOw
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}