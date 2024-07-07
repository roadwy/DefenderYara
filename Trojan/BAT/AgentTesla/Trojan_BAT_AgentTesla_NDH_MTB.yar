
rule Trojan_BAT_AgentTesla_NDH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {24 61 31 32 30 39 33 62 65 2d 36 66 64 61 2d 34 38 63 31 2d 39 62 31 64 2d 30 31 64 34 34 39 61 37 30 37 66 65 } //1 $a12093be-6fda-48c1-9b1d-01d449a707fe
		$a_01_1 = {53 79 73 74 65 6d 2e 57 69 6e 64 6f 77 73 2e 46 6f 72 6d 73 2e 46 6f 72 6d } //1 System.Windows.Forms.Form
		$a_01_2 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_7 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_8 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_9 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}