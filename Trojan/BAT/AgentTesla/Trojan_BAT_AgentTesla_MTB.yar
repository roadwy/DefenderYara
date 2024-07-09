
rule Trojan_BAT_AgentTesla_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 09 00 00 "
		
	strings :
		$a_03_0 = {16 2d 43 00 38 a2 ?? ?? 00 72 7d ?? ?? 70 38 9e ?? ?? 00 38 a3 ?? ?? 00 38 a4 ?? ?? 00 72 e3 ?? ?? 70 38 a4 ?? ?? 00 38 a9 ?? ?? 00 38 aa ?? ?? 00 8e 69 15 } //2
		$a_01_1 = {07 8e 69 5d 91 06 11 04 91 61 d2 9c } //2
		$a_01_2 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_3 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
		$a_01_4 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_5 = {47 65 74 44 69 72 65 63 74 6f 72 79 4e 61 6d 65 } //1 GetDirectoryName
		$a_01_6 = {45 6e 63 6f 64 69 6e 67 } //1 Encoding
		$a_01_7 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_80_8 = {68 74 74 70 3a 2f 2f 74 6c 73 70 72 6f 74 65 63 74 67 6f 2e 78 79 7a 2f 45 6d 45 36 64 2f 4d 64 64 6f 72 79 7a 5f 56 62 69 6c 76 76 78 73 2e 6a 70 67 } //http://tlsprotectgo.xyz/EmE6d/Mddoryz_Vbilvvxs.jpg  1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_80_8  & 1)*1) >=11
 
}
rule Trojan_BAT_AgentTesla_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {d0 01 00 00 02 28 d1 00 00 0a 6f 8e 05 00 0a fe 0e 00 00 20 08 00 00 00 8d b5 00 00 01 80 8d 03 00 04 7e 8d 03 00 04 20 00 00 00 00 11 00 20 d1 00 00 0a 6f 8f 05 00 0a 6f 90 05 00 0a 13 01 12 01 } //1
		$a_01_1 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_2 = {44 65 62 75 67 67 65 72 } //1 Debugger
		$a_01_3 = {67 65 74 5f 4d 61 6e 61 67 65 64 54 68 72 65 61 64 49 64 } //1 get_ManagedThreadId
		$a_01_4 = {49 6e 69 74 69 61 6c 69 7a 65 41 72 72 61 79 } //1 InitializeArray
		$a_01_5 = {54 6f 49 6e 74 33 32 } //1 ToInt32
		$a_01_6 = {45 6e 63 6f 64 69 6e 67 } //1 Encoding
		$a_01_7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_8 = {47 65 74 49 4c 47 65 6e 65 72 61 74 6f 72 } //1 GetILGenerator
		$a_01_9 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //1 LoadLibrary
		$a_01_10 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
		$a_01_11 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}