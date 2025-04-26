
rule Trojan_BAT_Remcos_STR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.STR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_81_0 = {52 61 77 4b 65 79 62 6f 61 72 64 } //1 RawKeyboard
		$a_81_1 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //1 GetKeyboardState
		$a_81_2 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_3 = {43 6f 6e 76 65 72 74 54 6f 53 74 72 69 6e 67 } //1 ConvertToString
		$a_81_4 = {41 73 79 6e 63 43 61 6c 6c 62 61 63 6b } //1 AsyncCallback
		$a_81_5 = {52 61 77 69 6e 70 75 74 68 65 61 64 65 72 } //1 Rawinputheader
		$a_81_6 = {56 69 72 74 75 61 6c 4b 65 79 43 6f 72 72 65 63 74 69 6f 6e } //1 VirtualKeyCorrection
		$a_81_7 = {4f 70 65 6e 53 75 62 4b 65 79 } //1 OpenSubKey
		$a_81_8 = {76 69 72 74 75 61 6c 4b 65 79 } //1 virtualKey
		$a_81_9 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //1 get_Assembly
		$a_81_10 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_11 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 MD5CryptoServiceProvider
		$a_00_12 = {24 35 62 65 36 63 61 31 37 2d 35 64 64 31 2d 34 38 38 31 2d 39 34 63 63 2d 33 39 38 34 63 63 38 64 36 35 65 32 } //1 $5be6ca17-5dd1-4881-94cc-3984cc8d65e2
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_00_12  & 1)*1) >=13
 
}