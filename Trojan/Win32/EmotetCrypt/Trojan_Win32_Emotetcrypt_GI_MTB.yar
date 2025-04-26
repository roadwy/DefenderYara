
rule Trojan_Win32_Emotetcrypt_GI_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 30 00 00 8b 4d ?? 8b 51 ?? 52 8b 45 ?? 8b 48 ?? 51 ff 15 } //1
		$a_00_1 = {f3 a4 8b 44 24 0c 5e 5f c3 } //1
		$a_00_2 = {83 c4 0c 8b 4d f0 83 c1 28 89 4d f0 eb } //1
		$a_00_3 = {89 45 fc 8b 55 10 52 8b 45 0c 50 8b 4d 08 51 ff 55 fc } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule Trojan_Win32_Emotetcrypt_GI_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 30 00 00 8b ?? ?? 8b ?? ?? ?? 8b ?? ?? 8b ?? ?? ?? ff 15 } //1
		$a_00_1 = {f3 a4 8b 44 24 0c 5e 5f c3 } //10
		$a_02_2 = {83 c4 0c 8b ?? ?? 83 ?? 28 89 ?? ?? eb } //1
		$a_00_3 = {89 45 fc 8b 55 10 52 8b 45 0c 50 8b 4d 08 51 ff 55 fc } //10
		$a_01_4 = {43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5f 00 52 00 75 00 6e 00 44 00 4c 00 4c 00 } //1 Control_RunDLL
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*10+(#a_02_2  & 1)*1+(#a_00_3  & 1)*10+(#a_01_4  & 1)*1+(#a_80_5  & 1)*1) >=24
 
}
rule Trojan_Win32_Emotetcrypt_GI_MTB_3{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 2a 03 c2 99 bd ?? ?? ?? ?? f7 fd 8b c1 0f af c3 83 c0 02 0f af c7 83 c0 02 0f af 05 ?? ?? ?? ?? 2b f0 8d 44 1b 02 0f af c3 03 44 24 2c 2b f1 0f af 0d ?? ?? ?? ?? 2b f7 8d 14 72 03 c2 8d 0c 89 0f b6 14 01 8b 44 24 20 30 10 } //1
		$a_81_1 = {21 50 21 38 68 21 61 74 2a 68 64 53 74 3c 61 39 45 6b 40 62 46 36 21 76 75 4b 6a 6e 78 74 64 39 55 2b 5e 52 46 66 25 49 26 24 48 39 78 5e 23 35 6e 48 3e 5f 43 73 47 71 6d 35 59 54 78 5f 76 69 45 28 37 39 51 75 2b 58 45 4f 30 } //1 !P!8h!at*hdSt<a9Ek@bF6!vuKjnxtd9U+^RFf%I&$H9x^#5nH>_CsGqm5YTx_viE(79Qu+XEO0
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}