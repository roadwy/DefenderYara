
rule Trojan_Win32_Delfinject_AD_MTB{
	meta:
		description = "Trojan:Win32/Delfinject.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {70 6d 4e 6f 74 43 6f 70 79 } //pmNotCopy  3
		$a_80_1 = {71 6a 68 74 68 68 70 6b 6a 71 6b 6d 70 69 6c 72 } //qjhthhpkjqkmpilr  3
		$a_80_2 = {57 69 6e 48 65 6c 70 56 69 65 77 65 72 } //WinHelpViewer  3
		$a_80_3 = {55 72 6c 4d 6f 6e } //UrlMon  3
		$a_80_4 = {6d 6b 75 6f 6d 74 6f } //mkuomto  3
		$a_80_5 = {6b 69 70 69 68 70 68 } //kipihph  3
		$a_80_6 = {68 6d 77 68 6e 70 6d } //hmwhnpm  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}
rule Trojan_Win32_Delfinject_AD_MTB_2{
	meta:
		description = "Trojan:Win32/Delfinject.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {47 6c 79 70 68 2e 44 61 74 61 } //Glyph.Data  3
		$a_80_1 = {57 69 6e 48 74 74 70 43 72 61 63 6b 55 72 6c } //WinHttpCrackUrl  3
		$a_80_2 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //LockResource  3
		$a_00_3 = {5a 00 5f 00 57 00 45 00 5a } //3
		$a_80_4 = {56 4d 6d 55 53 57 55 53 57 56 4d 6d 61 } //VMmUSWUSWVMma  3
		$a_80_5 = {47 65 74 4b 65 79 62 6f 61 72 64 54 79 70 65 } //GetKeyboardType  3
		$a_80_6 = {43 6f 70 79 45 6e 68 4d 65 74 61 46 69 6c 65 41 } //CopyEnhMetaFileA  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_00_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}
rule Trojan_Win32_Delfinject_AD_MTB_3{
	meta:
		description = "Trojan:Win32/Delfinject.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {4d 61 67 65 6c 6c 61 6e 20 4d 53 57 48 45 45 4c } //Magellan MSWHEEL  3
		$a_80_1 = {6c 6c 64 2e 69 73 6d 61 5c 32 33 6d 65 74 73 79 53 5c 73 77 6f 64 6e 69 57 5c 3a 43 } //lld.isma\23metsyS\swodniW\:C  3
		$a_80_2 = {4b 69 6c 6c 54 69 6d 65 72 } //KillTimer  3
		$a_80_3 = {4d 46 43 72 65 61 74 65 33 47 50 4d 65 64 69 61 53 69 6e 6b } //MFCreate3GPMediaSink  3
		$a_80_4 = {57 69 6e 48 74 74 70 43 68 65 63 6b 50 6c 61 74 66 6f 72 6d } //WinHttpCheckPlatform  3
		$a_80_5 = {69 6c 69 61 40 76 61 6c 6c 65 79 2e 72 75 } //ilia@valley.ru  3
		$a_80_6 = {70 6b 7c 53 49 70 51 48 68 4e 42 44 } //pk|SIpQHhNBD  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}