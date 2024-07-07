
rule Trojan_BAT_AgentTesla_LIB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_01_0 = {24 32 65 30 31 34 34 65 33 2d 31 36 38 61 2d 34 66 61 34 2d 61 31 36 65 2d 39 35 35 62 31 30 30 32 38 37 36 62 } //10 $2e0144e3-168a-4fa4-a16e-955b1002876b
		$a_01_1 = {24 64 62 36 39 35 32 34 63 2d 63 34 64 66 2d 34 34 66 31 2d 39 33 31 38 2d 33 65 30 32 32 61 34 36 32 66 34 32 } //10 $db69524c-c4df-44f1-9318-3e022a462f42
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_3 = {54 6f 57 69 6e 33 32 } //1 ToWin32
		$a_01_4 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //1 ColorTranslator
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=15
 
}