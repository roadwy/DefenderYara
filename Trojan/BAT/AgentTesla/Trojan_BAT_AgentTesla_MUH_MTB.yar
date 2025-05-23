
rule Trojan_BAT_AgentTesla_MUH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MUH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 11 00 00 "
		
	strings :
		$a_80_0 = {41 73 73 65 6d 62 6c 79 } //Assembly  1
		$a_80_1 = {54 63 70 43 68 61 6e 6e 65 6c } //TcpChannel  1
		$a_80_2 = {42 69 74 6d 61 70 } //Bitmap  1
		$a_80_3 = {50 75 70 70 65 74 4d 61 73 74 65 72 2e 57 61 72 64 2e 72 65 73 6f 75 72 63 65 73 } //PuppetMaster.Ward.resources  1
		$a_80_4 = {47 65 74 4f 62 6a 65 63 74 } //GetObject  1
		$a_80_5 = {53 6c 65 65 70 } //Sleep  1
		$a_80_6 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //set_UseShellExecute  1
		$a_80_7 = {67 65 74 5f 42 6c 61 63 6b } //get_Black  1
		$a_80_8 = {67 65 74 5f 52 65 64 } //get_Red  1
		$a_80_9 = {4c 61 74 65 47 65 74 } //LateGet  1
		$a_80_10 = {47 65 74 54 79 70 65 73 } //GetTypes  1
		$a_80_11 = {47 65 74 4d 65 74 68 6f 64 73 } //GetMethods  1
		$a_80_12 = {6f 70 5f 49 6e 65 71 75 61 6c 69 74 79 } //op_Inequality  1
		$a_80_13 = {4f 20 51 27 54 29 55 2a 59 2b 5d 2d 64 30 65 33 66 37 67 38 } //O Q'T)U*Y+]-d0e3f7g8  1
		$a_80_14 = {5d 61 5d 62 5d 63 5d 68 67 76 75 } //]a]b]c]hgvu  1
		$a_80_15 = {74 63 70 3a 2f 2f 6c 6f 63 61 6c 68 6f 73 74 3a } //tcp://localhost:  1
		$a_80_16 = {50 75 70 70 65 74 4d 61 73 74 65 72 4d 61 73 74 65 72 } //PuppetMasterMaster  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1+(#a_80_15  & 1)*1+(#a_80_16  & 1)*1) >=17
 
}