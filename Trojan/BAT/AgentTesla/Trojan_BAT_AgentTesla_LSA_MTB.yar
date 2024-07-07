
rule Trojan_BAT_AgentTesla_LSA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {24 35 65 65 34 39 62 33 32 2d 35 63 35 33 2d 34 64 37 36 2d 38 31 65 33 2d 62 62 32 66 36 30 64 62 36 63 63 63 } //1 $5ee49b32-5c53-4d76-81e3-bb2f60db6ccc
		$a_01_1 = {53 75 73 70 65 6e 64 4c 61 79 6f 75 74 } //1 SuspendLayout
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_3 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //1 ColorTranslator
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}