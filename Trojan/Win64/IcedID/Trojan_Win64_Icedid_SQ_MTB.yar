
rule Trojan_Win64_Icedid_SQ_MTB{
	meta:
		description = "Trojan:Win64/Icedid.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c1 03 0d ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 44 ?? ?? 44 ?? ?? 44 ?? ?? 01 d1 2b 4c 24 ?? 48 ?? ?? 8a 04 08 42 ?? ?? ?? 49 ?? ?? 88 44 1d ?? e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Icedid_SQ_MTB_2{
	meta:
		description = "Trojan:Win64/Icedid.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,26 00 26 00 07 00 00 "
		
	strings :
		$a_03_0 = {45 33 c9 48 ?? ?? ?? ?? 45 33 c0 33 c9 41 8d ?? ?? ff 15 ?? ?? 00 00 48 8b cb 48 8d 15 ?? ?? 00 00 85 c0 75 ?? 48 8d 15 ?? ?? 00 00 ff 15 ?? ?? 00 00 48 8d 57 04 48 8b ce ff 15 ?? ?? 00 00 ba 22 00 00 00 48 8b ce ff 15 } //20
		$a_01_1 = {63 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c } //5 c:\ProgramData\
		$a_01_2 = {73 61 64 6c 5f 36 34 2e 64 6c 6c } //5 sadl_64.dll
		$a_01_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //5 DllRegisterServer
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_5 = {43 72 65 61 74 65 54 68 72 65 61 64 } //1 CreateThread
		$a_01_6 = {53 48 47 65 74 46 6f 6c 64 65 72 50 61 74 68 41 } //1 SHGetFolderPathA
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=38
 
}