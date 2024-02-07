
rule Trojan_Win64_Icedid_SQ_MTB{
	meta:
		description = "Trojan:Win64/Icedid.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 c1 03 0d 90 01 04 48 90 01 06 44 90 01 02 44 90 01 02 44 90 01 02 01 d1 2b 4c 24 90 01 01 48 90 01 02 8a 04 08 42 90 01 03 49 90 01 02 88 44 1d 90 01 01 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Icedid_SQ_MTB_2{
	meta:
		description = "Trojan:Win64/Icedid.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,26 00 26 00 07 00 00 14 00 "
		
	strings :
		$a_03_0 = {45 33 c9 48 90 01 04 45 33 c0 33 c9 41 8d 90 01 02 ff 15 90 01 02 00 00 48 8b cb 48 8d 15 90 01 02 00 00 85 c0 75 90 01 01 48 8d 15 90 01 02 00 00 ff 15 90 01 02 00 00 48 8d 57 04 48 8b ce ff 15 90 01 02 00 00 ba 22 00 00 00 48 8b ce ff 15 90 00 } //05 00 
		$a_01_1 = {63 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c } //05 00  c:\ProgramData\
		$a_01_2 = {73 61 64 6c 5f 36 34 2e 64 6c 6c } //05 00  sadl_64.dll
		$a_01_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_5 = {43 72 65 61 74 65 54 68 72 65 61 64 } //01 00  CreateThread
		$a_01_6 = {53 48 47 65 74 46 6f 6c 64 65 72 50 61 74 68 41 } //00 00  SHGetFolderPathA
	condition:
		any of ($a_*)
 
}