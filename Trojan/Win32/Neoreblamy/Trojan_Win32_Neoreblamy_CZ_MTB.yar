
rule Trojan_Win32_Neoreblamy_CZ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e0 03 45 f4 c6 00 eb 0f b6 45 ff 48 48 8b 4d e0 03 4d f4 88 41 01 0f b6 45 ff 03 45 f4 89 45 f4 eb } //2
		$a_01_1 = {47 50 76 73 50 46 71 77 74 73 4d 6c 4b 4f 51 71 5a 55 49 59 42 4f 74 42 71 77 64 6c } //1 GPvsPFqwtsMlKOQqZUIYBOtBqwdl
		$a_01_2 = {53 4f 72 47 6d 57 5a 72 43 5a 53 67 6d 45 42 58 64 4b 4e 5a 4c 45 6f 4f 77 46 4d 55 } //1 SOrGmWZrCZSgmEBXdKNZLEoOwFMU
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}