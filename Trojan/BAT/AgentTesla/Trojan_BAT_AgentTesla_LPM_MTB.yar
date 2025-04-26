
rule Trojan_BAT_AgentTesla_LPM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {24 61 37 61 38 35 32 37 63 2d 33 37 61 65 2d 34 34 33 62 2d 38 64 61 61 2d 36 31 30 30 31 63 62 64 32 36 35 38 } //1 $a7a8527c-37ae-443b-8daa-61001cbd2658
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_5 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //1 ColorTranslator
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}