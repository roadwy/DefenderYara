
rule Trojan_BAT_AgentTesla_BA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {02 50 06 02 50 8e b7 6a 5d b7 02 50 06 02 50 8e b7 6a 5d b7 91 03 06 03 8e b7 6a 5d b7 91 61 02 50 06 17 6a d6 02 50 8e b7 6a 5d b7 91 da 20 ?? ?? ?? ?? d6 20 ?? ?? ?? ?? 5d b4 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_BAT_AgentTesla_BA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_00_0 = {57 bf a2 3d 09 0b 00 00 00 00 00 00 00 00 00 00 01 00 00 00 bb 00 00 00 40 00 00 00 c7 } //3
		$a_81_1 = {48 65 61 76 79 44 75 63 6b 2e 45 76 65 } //3 HeavyDuck.Eve
		$a_81_2 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //3 HttpWebRequest
		$a_81_3 = {57 65 62 52 65 71 75 65 73 74 } //3 WebRequest
		$a_81_4 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 50 65 72 6d 69 73 73 69 6f 6e 73 } //3 System.Security.Permissions
		$a_81_5 = {46 69 6c 65 49 4f 50 65 72 6d 69 73 73 69 6f 6e 41 63 63 65 73 73 } //3 FileIOPermissionAccess
	condition:
		((#a_00_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}
rule Trojan_BAT_AgentTesla_BA_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_00_0 = {57 95 a2 29 09 03 00 00 00 00 00 00 00 00 00 00 01 00 00 00 4a 00 00 00 11 00 00 00 54 } //3
		$a_81_1 = {48 4a 53 48 4a 53 4c 4b 57 2e 70 64 62 } //3 HJSHJSLKW.pdb
		$a_81_2 = {42 65 6c 6c 62 65 6c 6c 62 65 6c 6c } //3 Bellbellbell
		$a_81_3 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //3 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
		$a_81_4 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } //3 SecurityProtocolType
	condition:
		((#a_00_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3) >=15
 
}