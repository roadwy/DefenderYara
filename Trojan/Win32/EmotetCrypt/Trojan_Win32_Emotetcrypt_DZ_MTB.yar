
rule Trojan_Win32_Emotetcrypt_DZ_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 08 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b 4d f0 8b 51 50 52 8b 45 f0 8b 48 34 51 ff 15 } //10
		$a_03_1 = {8b 55 f0 0f b7 42 06 39 45 dc 7d ?? 8b 4d e4 8b 51 10 52 8b 45 e4 8b 48 14 03 4d ec 51 8b 55 e4 8b 42 0c 03 45 e8 ?? ?? ?? ?? 07 00 83 c4 0c 8b 4d e4 83 c1 28 89 4d e4 eb } //10
		$a_03_2 = {8b 4d dc 83 c1 01 89 4d dc 8b 55 f0 0f b7 42 06 39 45 dc 7d ?? 8b 4d e4 8b 51 10 52 8b 45 e4 8b 48 14 03 4d ec 51 8b 55 e4 8b 42 0c 03 45 e8 50 e8 ?? ?? ?? ?? 83 c4 0c 8b 4d e4 83 c1 28 89 4d e4 eb } //10
		$a_81_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_4 = {69 6e 66 6c 61 74 65 } //1 inflate
		$a_81_5 = {5f 6f 70 6a 5f 73 74 72 65 61 6d 5f 64 65 73 74 72 6f 79 40 34 } //1 _opj_stream_destroy@4
		$a_81_6 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_7 = {5a 3a 5c 63 72 5c 63 72 79 70 74 65 72 34 5c 62 61 6c 6c 61 73 74 5c 33 5c 6f 70 65 6e 6a 70 32 5c 6f 70 6a 5f 69 6e 74 6d 61 74 68 2e 68 } //1 Z:\cr\crypter4\ballast\3\openjp2\opj_intmath.h
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=25
 
}