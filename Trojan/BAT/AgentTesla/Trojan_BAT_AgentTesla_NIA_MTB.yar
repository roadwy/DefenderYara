
rule Trojan_BAT_AgentTesla_NIA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {50 6c 61 79 20 73 70 6c 69 74 73 63 72 65 65 6e 20 67 61 6d 65 73 20 6f 76 65 72 20 74 68 65 20 69 6e 74 65 72 6e 65 74 } //1 Play splitscreen games over the internet
		$a_01_1 = {53 70 6c 69 74 50 6c 61 79 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 SplitPlay.Resources.resources
		$a_01_2 = {24 64 65 33 30 31 61 63 34 2d 34 66 30 37 2d 34 30 32 65 2d 39 61 31 37 2d 63 37 31 34 31 32 65 31 39 30 36 63 } //1 $de301ac4-4f07-402e-9a17-c71412e1906c
		$a_01_3 = {53 70 6c 69 74 50 6c 61 79 2e 4d 79 } //1 SplitPlay.My
		$a_01_4 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_01_5 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_01_6 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_01_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_8 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_9 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}