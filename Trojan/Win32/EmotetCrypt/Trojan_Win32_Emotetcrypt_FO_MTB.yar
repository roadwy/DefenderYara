
rule Trojan_Win32_Emotetcrypt_FO_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.FO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 "
		
	strings :
		$a_81_0 = {66 63 72 35 76 69 63 68 6b 7a 2e 64 6c 6c } //10 fcr5vichkz.dll
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
		$a_81_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_4 = {52 61 69 73 65 45 78 63 65 70 74 69 6f 6e } //1 RaiseException
		$a_81_5 = {6d 79 38 70 61 34 72 73 66 64 73 6b 78 69 71 74 6d 77 70 6c 64 77 63 33 6e 6d 30 6a } //1 my8pa4rsfdskxiqtmwpldwc3nm0j
		$a_81_6 = {74 6f 64 61 72 64 67 38 34 71 68 78 6c 61 32 79 78 74 38 79 33 31 72 62 70 70 79 70 } //1 todardg84qhxla2yxt8y31rbppyp
		$a_81_7 = {75 6d 77 75 6f 65 31 62 37 75 31 66 35 63 78 66 36 34 61 7a 33 63 } //1 umwuoe1b7u1f5cxf64az3c
		$a_81_8 = {77 77 74 71 77 37 74 6c 34 68 62 6f 34 6f 35 76 32 74 79 6e 6b 35 35 79 36 6a 77 34 73 } //1 wwtqw7tl4hbo4o5v2tynk55y6jw4s
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=18
 
}