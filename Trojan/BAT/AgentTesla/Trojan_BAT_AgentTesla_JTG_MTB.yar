
rule Trojan_BAT_AgentTesla_JTG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JTG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {24 30 32 62 36 39 63 64 32 2d 65 66 39 36 2d 34 64 35 32 2d 62 34 64 39 2d 32 31 34 61 32 32 32 38 38 64 31 62 } //1 $02b69cd2-ef96-4d52-b4d9-214a22288d1b
		$a_01_1 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_2 = {47 65 74 53 74 72 69 6e 67 } //1 GetString
		$a_01_3 = {44 75 6f 20 42 69 7a 7a 20 53 6e 61 6b 65 } //1 Duo Bizz Snake
		$a_01_4 = {53 6f 6c 79 6d 6f 73 69 } //1 Solymosi
		$a_01_5 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_01_8 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_10 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}