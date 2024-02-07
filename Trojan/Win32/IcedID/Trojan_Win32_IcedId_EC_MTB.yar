
rule Trojan_Win32_IcedId_EC_MTB{
	meta:
		description = "Trojan:Win32/IcedId.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {83 c0 0e 66 89 44 24 30 3a db 74 d9 66 89 44 24 36 b8 1b 00 00 00 e9 1c 01 00 00 48 83 ec 68 48 c7 44 24 20 00 00 00 00 3a d2 74 00 48 c7 44 24 28 00 00 00 00 b8 23 00 00 00 3a ed 74 c2 } //01 00 
		$a_01_1 = {66 75 61 64 73 79 67 75 61 73 67 64 75 68 61 69 73 75 64 6a 79 75 61 67 73 64 75 61 } //00 00  fuadsyguasgduhaisudjyuagsdua
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_IcedId_EC_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 61 72 2e 64 6c 6c } //01 00  far.dll
		$a_01_1 = {44 65 73 65 72 74 } //01 00  Desert
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_3 = {46 72 75 69 74 62 6c 6f 77 } //01 00  Fruitblow
		$a_01_4 = {57 68 61 74 70 69 65 63 65 } //01 00  Whatpiece
		$a_01_5 = {47 65 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 56 61 72 69 61 62 6c 65 57 } //01 00  GetEnvironmentVariableW
		$a_01_6 = {43 72 65 61 74 65 4d 75 74 65 78 57 } //00 00  CreateMutexW
	condition:
		any of ($a_*)
 
}