
rule Trojan_BAT_AgentTesla_LUS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LUS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {23 66 61 73 66 64 6b 69 6f 69 6f 61 61 61 61 61 6f 61 61 61 64 73 73 73 61 66 2e 64 6c 6c 23 } //1 #fasfdkioioaaaaaoaaadsssaf.dll#
		$a_01_1 = {23 67 73 64 67 67 64 6c 6c 6c 6c 6c 6c 6c 6f 6b 6f 73 61 64 73 61 64 67 67 67 67 67 23 } //1 #gsdggdlllllllokosadsadggggg#
		$a_01_2 = {23 66 61 73 66 64 6b 6b 6c 6c 6a 69 64 64 64 64 64 64 64 73 73 61 66 2e 64 6c 6c 23 } //1 #fasfdkklljidddddddssaf.dll#
		$a_01_3 = {23 67 64 66 73 66 64 6c 6c 6c 3b 3b 3b 3b 6c 6c 6c 6c 6c 73 2e 64 6c 6c 23 } //1 #gdfsfdlll;;;;llllls.dll#
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_LUS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.LUS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {02 6c 23 ff ?? ?? ?? ?? ?? ?? 3f 5b 28 ?? ?? ?? 0a b7 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 07 0a 06 2a } //1
		$a_01_1 = {24 36 41 45 43 31 38 37 35 2d 37 38 30 33 2d 34 41 33 31 2d 42 45 32 32 2d 39 39 36 45 38 44 42 34 36 33 44 36 } //1 $6AEC1875-7803-4A31-BE22-996E8DB463D6
		$a_03_2 = {0a 13 04 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 13 05 07 11 05 28 ?? ?? ?? 0a 0b 09 17 d6 0d 09 08 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d cd } //1
		$a_01_3 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_01_4 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}