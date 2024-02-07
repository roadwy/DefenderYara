
rule Trojan_BAT_AgentTesla_NYO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NYO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 38 38 66 38 31 62 36 36 2d 35 62 65 63 2d 34 65 35 39 2d 38 36 32 61 2d 31 64 62 66 30 64 37 62 39 30 30 35 } //01 00  $88f81b66-5bec-4e59-862a-1dbf0d7b9005
		$a_01_1 = {15 b6 0b 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 92 00 00 00 13 } //01 00 
		$a_81_2 = {47 69 72 6c 66 72 69 65 6e 64 5f 49 73 5f 48 6f 72 6e 79 5f 53 74 65 70 5f 31 31 } //01 00  Girlfriend_Is_Horny_Step_11
		$a_81_3 = {44 53 48 53 41 44 4a 55 46 41 48 47 59 46 20 58 55 59 46 47 } //01 00  DSHSADJUFAHGYF XUYFG
		$a_81_4 = {42 75 6e 69 31 66 75 5f 54 65 31 78 74 42 31 6f 78 } //00 00  Buni1fu_Te1xtB1ox
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NYO_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NYO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 b5 a2 3f 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 4b 00 00 00 28 00 00 00 55 00 00 00 8a 00 00 00 cc 00 00 00 6a 00 00 00 19 00 00 00 03 00 00 00 04 00 00 00 1c 00 00 00 02 00 00 00 03 00 00 00 04 } //01 00 
		$a_01_1 = {44 65 66 6c 61 74 65 53 74 72 65 61 6d } //01 00  DeflateStream
		$a_01_2 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //01 00  GetManifestResourceStream
		$a_01_3 = {46 44 46 44 4b 4c 46 44 4b 44 46 4c 4b 45 52 45 52 52 47 44 46 44 46 } //01 00  FDFDKLFDKDFLKERERRGDFDF
		$a_01_4 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 20 31 2e 36 2e 30 2b 34 34 37 33 34 31 39 36 34 66 } //00 00  Confuser.Core 1.6.0+447341964f
	condition:
		any of ($a_*)
 
}