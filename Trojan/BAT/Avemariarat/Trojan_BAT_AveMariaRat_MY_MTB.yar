
rule Trojan_BAT_AveMariaRat_MY_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRat.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_03_0 = {08 07 2b 03 00 2b 07 6f ?? ?? ?? 0a 2b f6 00 de 11 08 2b 08 08 6f ?? ?? ?? 0a 2b 04 2c 03 2b f4 00 dc 07 6f ?? ?? ?? 0a 0d de 1c } //1
		$a_01_1 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_2 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_3 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //1 DynamicInvoke
		$a_01_4 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_5 = {54 68 72 65 61 64 57 61 73 53 75 73 70 65 6e 64 65 64 } //1 ThreadWasSuspended
		$a_01_6 = {44 65 62 75 67 67 65 72 49 6e 61 63 74 69 76 65 } //1 DebuggerInactive
		$a_01_7 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_8 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_01_9 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}