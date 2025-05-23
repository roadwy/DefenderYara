
rule Trojan_Win64_Cobaltstrike_RN_dha{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RN!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {48 29 d0 40 32 34 04 89 f0 41 31 c0 45 88 04 ?? 48 83 c1 01 45 89 ?? 41 39 } //1
		$a_03_1 = {4a 46 49 46 c6 44 24 ?? ?? e8 ?? ?? ?? ?? 85 c0 [0-0a] c6 05 ?? ?? ?? ?? 6a c6 05 ?? ?? ?? ?? 70 } //1
		$a_03_2 = {ff 85 c0 75 ?? 8b 44 24 ?? 48 8b 4c 24 ?? 45 31 c0 48 01 c8 8d 14 01 48 63 d2 48 89 15 ?? ?? ?? ?? ba 01 00 00 00 ff d0 } //1
		$a_03_3 = {c1 e9 10 a9 80 80 00 00 0f 44 c1 48 8d 4a 02 89 ?? 48 0f 44 d1 40 00 ?? 48 8b 05 ?? 48 83 da 03 c7 02 41 6c 6c 6f 66 } //1
		$a_02_4 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 [0-20] 2e 6a 70 67 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_02_4  & 1)*1) >=3
 
}
rule Trojan_Win64_Cobaltstrike_RN_dha_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RN!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 89 c8 45 0f b6 4c 0a 30 48 [0-30] 89 ?? 41 31 c0 45 88 04 0a 48 83 c1 01 45 89 c8 41 39 cb 7f ?? 31 c0 48 81 c4 ?? 00 00 00 5b 5e 5f c3 } //1
		$a_03_1 = {48 b8 53 4f 46 54 57 41 52 45 c7 44 24 60 66 74 5c 43 c6 44 24 66 00 48 89 44 24 50 48 b8 5c 4d 69 63 72 6f 73 6f 4c 8d 44 24 48 48 89 44 24 58 b8 54 46 00 00 ?? 89 ea 66 89 44 24 64 48 c7 c1 01 00 00 80 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 31 c0 } //1
		$a_03_2 = {09 05 00 d8 0f 85 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 41 b8 04 00 00 00 48 89 ?? c7 44 24 70 4a 46 49 46 c6 44 24 74 00 e8 ?? ?? ?? ?? 85 c0 0f 85 ?? ?? ?? ?? c6 05 ?? ?? 05 00 6a c6 05 ?? ?? 05 00 70 c6 05 ?? ?? 05 00 65 c6 05 ?? ?? 05 00 67 e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}