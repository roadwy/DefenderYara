
rule Trojan_Win32_Emotetcrypt_EK_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 0a 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_81_1 = {50 72 6f 6a 65 63 74 31 2e 64 6c 6c } //01 00  Project1.dll
		$a_81_2 = {5f 5a 4e 38 44 6c 6c 43 6c 61 73 73 31 30 48 65 6c 6c 6f 57 6f 72 6c 64 45 76 } //01 00  _ZN8DllClass10HelloWorldEv
		$a_81_3 = {5f 5a 4e 38 44 6c 6c 43 6c 61 73 73 43 31 45 76 } //01 00  _ZN8DllClassC1Ev
		$a_81_4 = {5f 5a 4e 38 44 6c 6c 43 6c 61 73 73 44 30 45 76 } //01 00  _ZN8DllClassD0Ev
		$a_81_5 = {5f 5a 54 49 38 44 6c 6c 43 6c 61 73 73 } //01 00  _ZTI8DllClass
		$a_81_6 = {7a 66 64 6d 63 6d 66 6e 75 70 7a 67 71 7a 6c 74 65 69 70 64 62 6f 72 2e 64 6c 6c } //01 00  zfdmcmfnupzgqzlteipdbor.dll
		$a_81_7 = {6b 6c 65 69 6e 78 72 67 77 6c 68 69 6f 70 66 } //01 00  kleinxrgwlhiopf
		$a_81_8 = {72 76 71 78 64 65 6c 6e 70 63 79 62 69 77 6c 66 } //01 00  rvqxdelnpcybiwlf
		$a_81_9 = {75 62 70 79 61 65 70 61 67 76 6c 65 6e 6c 6e } //01 00  ubpyaepagvlenln
		$a_81_10 = {79 66 70 6a 63 79 79 6d 68 68 75 74 } //00 00  yfpjcyymhhut
	condition:
		any of ($a_*)
 
}