
rule Trojan_Win32_Emotetcrypt_DY_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_00_0 = {6a 04 68 00 30 00 00 6a 0a 6a 00 8b 45 08 8b 48 18 ff d1 } //1
		$a_02_1 = {8b d1 80 7a 0c 00 75 ?? 33 c0 66 0f 1f 44 00 00 8b 0c 82 81 f1 e4 ed 77 3f 89 0c 82 40 83 f8 03 72 } //1
		$a_81_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_3 = {6b 61 6f 64 33 72 33 79 30 38 63 62 30 71 78 39 6c 6c 6f 68 61 38 68 34 36 61 } //1 kaod3r3y08cb0qx9lloha8h46a
		$a_81_4 = {65 79 37 39 6e 34 79 39 77 67 30 61 77 6f 77 6a 64 61 30 30 77 71 72 6d 68 36 70 74 39 67 38 } //1 ey79n4y9wg0awowjda00wqrmh6pt9g8
		$a_81_5 = {63 38 61 32 6a 6b 7a 37 62 71 35 35 37 63 35 66 38 6d 7a 7a 7a 67 6f 64 65 78 6f 37 33 79 } //1 c8a2jkz7bq557c5f8mzzzgodexo73y
		$a_81_6 = {78 67 78 64 39 37 35 72 78 61 6a 6e 73 39 62 7a 68 70 66 7a 61 61 76 72 75 70 66 } //1 xgxd975rxajns9bzhpfzaavrupf
		$a_81_7 = {77 71 39 6f 6d 31 30 6e 32 38 31 68 } //1 wq9om10n281h
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=7
 
}