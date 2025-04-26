
rule Trojan_Win32_Gozi_RA_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b8 e1 bf 01 00 [0-0a] 8a 04 08 88 04 0a } //1
		$a_01_1 = {bd 00 01 00 00 88 80 78 b7 21 02 40 3b c5 75 } //1
		$a_01_2 = {30 04 37 4e 0f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Gozi_RA_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 04 0a 8b f8 85 c0 75 0a c7 44 24 10 01 00 00 00 eb 0d 2b 74 24 0c 03 c6 89 01 8b f7 83 c1 04 ff 4c 24 10 75 da } //1
		$a_01_1 = {8b 4d e0 8b 41 0c 2b 41 08 81 45 f8 00 10 00 00 03 41 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Gozi_RA_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 ff 75 ?? 57 ff 55 ?? 33 c9 8b f0 39 7d ?? 76 1d 8b c1 99 6a 3c 5f f7 ff 8a 82 ?? ?? ?? ?? 8b 55 ?? 32 04 11 88 04 31 41 3b 4d ?? 72 e3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Gozi_RA_MTB_4{
	meta:
		description = "Trojan:Win32/Gozi.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 46 48 51 64 6f 6b 6d 2e 64 6c 6c } //1 BFHQdokm.dll
		$a_01_1 = {41 77 63 4e 32 7a 6e 50 77 43 63 } //1 AwcN2znPwCc
		$a_01_2 = {44 52 47 55 34 4b 6a 5a 61 70 7a 62 39 77 } //1 DRGU4KjZapzb9w
		$a_01_3 = {47 53 51 59 4f 4b 34 52 59 38 49 74 51 38 37 69 } //1 GSQYOK4RY8ItQ87i
		$a_01_4 = {48 34 6c 7a 47 54 38 52 52 55 66 6b 62 4f 39 } //1 H4lzGT8RRUfkbO9
		$a_01_5 = {58 79 43 6b 46 66 42 70 70 54 70 63 78 67 37 } //1 XyCkFfBppTpcxg7
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win32_Gozi_RA_MTB_5{
	meta:
		description = "Trojan:Win32/Gozi.RA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ce 81 c2 d6 04 00 00 8b de 2b ca 2b dd 81 e9 68 da 00 00 83 c3 07 57 8d 3c 00 2b fa 8d 04 49 03 fe c1 e0 04 81 c1 28 c2 01 00 2b c6 05 d6 04 00 00 0f b7 c0 03 c7 03 c6 03 c8 5f 5e 8d 04 29 81 c1 1d e4 00 00 8d 04 40 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}