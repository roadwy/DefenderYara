
rule Trojan_Win32_ClipBanker_ABM_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 09 00 00 "
		
	strings :
		$a_80_0 = {40 20 43 20 4f 20 4d 20 52 } //@ C O M R  3
		$a_80_1 = {49 63 6d 70 43 72 65 61 74 65 46 69 6c 65 } //IcmpCreateFile  3
		$a_80_2 = {49 6e 74 65 72 6e 65 74 51 75 65 72 79 44 61 74 61 41 76 61 69 6c 61 62 6c 65 } //InternetQueryDataAvailable  3
		$a_80_3 = {57 4e 65 74 55 73 65 43 6f 6e 6e 65 63 74 69 6f 6e 57 } //WNetUseConnectionW  3
		$a_80_4 = {47 65 74 55 73 65 72 4f 62 6a 65 63 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 57 } //GetUserObjectInformationW  3
		$a_80_5 = {44 65 73 74 72 6f 79 45 6e 76 69 72 6f 6e 6d 65 6e 74 42 6c 6f 63 6b } //DestroyEnvironmentBlock  3
		$a_80_6 = {43 6f 54 61 73 6b 4d 65 6d 41 6c 6c 6f 63 } //CoTaskMemAlloc  3
		$a_80_7 = {57 53 4f 43 4b 33 32 2e 64 6c 6c } //WSOCK32.dll  3
		$a_80_8 = {35 67 49 6b 76 55 35 } //5gIkvU5  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*3) >=27
 
}