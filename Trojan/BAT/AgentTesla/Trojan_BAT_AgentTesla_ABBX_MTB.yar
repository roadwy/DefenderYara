
rule Trojan_BAT_AgentTesla_ABBX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_1 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_01_2 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //1 FlushFinalBlock
		$a_01_3 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //1 GetManifestResourceStream
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {41 76 61 6c 6f 6e 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 Avalon.g.resources
		$a_01_6 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_7 = {24 31 33 34 34 63 32 36 38 2d 63 38 39 35 2d 34 61 30 39 2d 38 31 34 37 2d 34 63 61 38 61 64 62 33 39 34 64 61 } //1 $1344c268-c895-4a09-8147-4ca8adb394da
		$a_01_8 = {52 00 75 00 6e 00 6e 00 65 00 72 00 } //1 Runner
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}