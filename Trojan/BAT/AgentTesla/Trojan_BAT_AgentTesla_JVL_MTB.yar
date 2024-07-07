
rule Trojan_BAT_AgentTesla_JVL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JVL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {0a 07 da 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0a 00 09 17 d6 0d 09 08 6f 90 01 03 0a fe 04 13 05 90 00 } //1
		$a_81_1 = {24 32 32 39 66 62 38 36 30 2d 65 62 39 39 2d 34 66 34 38 2d 61 66 62 32 2d 66 30 66 61 34 31 30 66 33 64 66 65 } //1 $229fb860-eb99-4f48-afb2-f0fa410f3dfe
		$a_81_2 = {48 4a 44 2e 50 65 78 65 73 6f 2e 46 6f 72 6d 47 55 49 } //1 HJD.Pexeso.FormGUI
		$a_81_3 = {68 00 78 00 2e 00 6a 00 39 } //1
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_6 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_81_7 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}