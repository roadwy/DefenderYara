
rule Backdoor_Linux_Mirai_BL_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.BL!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 73 6e 63 74 6f 64 74 6f 65 75 70 65 75 70 65 75 70 } //01 00  dsnctodtoeupeupeup
		$a_00_1 = {76 66 6d 67 75 66 6e 68 76 67 6e 68 77 68 6f 69 77 68 6f 69 77 68 6f 69 } //01 00  vfmgufnhvgnhwhoiwhoiwhoi
		$a_00_2 = {31 76 65 71 68 62 6e 66 30 76 65 71 69 63 6f 67 31 77 66 72 69 63 6f 67 32 78 67 73 6a 64 70 68 32 78 67 73 6a 64 70 68 32 78 67 73 6a 64 70 68 } //02 00  1veqhbnf0veqicog1wfricog2xgsjdph2xgsjdph2xgsjdph
		$a_00_3 = {89 e8 8b 7c 24 50 89 f2 25 ff f7 f7 ff 89 44 24 10 8b 44 24 58 8d 4c 24 0c c7 44 24 18 00 00 00 00 89 7c 24 0c c7 44 24 1c 00 00 00 00 89 44 24 14 89 d8 c7 44 24 20 00 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}