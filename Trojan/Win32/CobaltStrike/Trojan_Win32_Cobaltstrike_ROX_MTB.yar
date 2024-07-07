
rule Trojan_Win32_Cobaltstrike_ROX_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.ROX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_81_0 = {53 65 72 76 65 72 43 6f 6d 70 75 74 65 72 } //1 ServerComputer
		$a_81_1 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //1 GetAsyncKeyState
		$a_81_2 = {4e 65 74 77 6f 72 6b 53 74 72 65 61 6d } //1 NetworkStream
		$a_81_3 = {49 41 73 79 6e 63 52 65 73 75 6c 74 } //1 IAsyncResult
		$a_81_4 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_5 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //1 ContainsKey
		$a_81_6 = {57 72 69 74 65 41 6c 6c 54 65 78 74 } //1 WriteAllText
		$a_81_7 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_81_8 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_9 = {4c 6f 61 64 65 64 20 73 65 74 74 69 6e 67 73 20 66 72 6f 6d 20 72 65 67 69 73 74 72 79 } //1 Loaded settings from registry
		$a_00_10 = {24 66 65 35 33 65 31 34 31 2d 38 38 31 32 2d 34 39 30 66 2d 61 65 37 61 2d 35 36 32 37 61 37 39 34 30 39 32 65 } //1 $fe53e141-8812-490f-ae7a-5627a794092e
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_00_10  & 1)*1) >=11
 
}