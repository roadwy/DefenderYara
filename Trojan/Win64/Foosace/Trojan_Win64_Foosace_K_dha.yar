
rule Trojan_Win64_Foosace_K_dha{
	meta:
		description = "Trojan:Win64/Foosace.K!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {48 b9 22 2c 20 49 6e 69 74 57 48 89 4c 38 0e 66 c7 44 38 16 20 00 } //1
		$a_03_1 = {48 b8 33 32 2e 45 58 45 20 22 48 89 85 ?? ?? ?? ?? 48 b8 52 55 4e 44 4c 4c 33 32 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win64_Foosace_K_dha_2{
	meta:
		description = "Trojan:Win64/Foosace.K!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 6e 69 74 57 00 52 65 67 69 73 74 65 72 4e 65 77 43 6f 6d 6d 61 6e 64 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 } //2 湉瑩W敒楧瑳牥敎䍷浯慭摮䐀汬慃啮汮慯乤睯䐀汬敇䍴慬獳扏敪瑣
		$a_03_1 = {41 b8 06 00 00 00 41 f7 f0 8b c2 8b c0 48 8b 54 24 ?? 0f b6 04 02 33 c8 } //1
		$a_03_2 = {b8 f4 ee ee ee eb 14 44 8b 44 24 ?? 48 8b 54 24 ?? 48 8b 4c 24 ?? e8 ?? ?? ?? ?? 48 83 c4 38 c3 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}
rule Trojan_Win64_Foosace_K_dha_3{
	meta:
		description = "Trojan:Win64/Foosace.K!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 c7 44 c8 08 10 00 00 00 8b ca 48 03 c9 ff c2 48 8d 05 ?? ?? ?? ?? 49 89 04 c8 41 c7 44 c8 08 15 00 00 00 8b ca 48 03 c9 ff c2 } //1
		$a_03_1 = {48 89 81 28 02 00 00 48 85 c0 0f 84 ?? 00 00 00 48 8b 0d ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8b 0d ?? ?? ?? ?? 48 89 81 00 03 00 00 } //1
		$a_03_2 = {78 02 00 00 33 d2 44 8b c0 48 8b 05 ?? ?? ?? ?? 8d 4a 01 ff 90 90 10 02 00 00 90 09 02 00 ff 90 90 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}