
rule Trojan_BAT_NanoCore_MA_MTB{
	meta:
		description = "Trojan:BAT/NanoCore.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {48 00 79 00 54 00 33 00 4e 00 47 00 6e 00 42 00 54 00 59 00 48 00 58 00 63 00 4a 00 77 00 46 00 59 00 76 00 } //1 HyT3NGnBTYHXcJwFYv
		$a_01_1 = {76 00 68 00 4f 00 78 00 52 00 44 00 32 00 6a 00 35 00 52 00 70 00 78 00 71 00 33 00 4c 00 53 00 41 00 43 00 } //1 vhOxRD2j5Rpxq3LSAC
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_5 = {44 65 62 75 67 67 65 72 } //1 Debugger
		$a_01_6 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_01_7 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_8 = {73 65 74 5f 4b 65 79 } //1 set_Key
		$a_01_9 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_10 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_11 = {4e 61 6e 6f 43 6f 72 65 2e 53 65 72 76 65 72 50 6c 75 67 69 6e 48 6f 73 74 } //1 NanoCore.ServerPluginHost
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}