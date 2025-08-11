
rule Trojan_Win64_ClipBanker_C_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 81 ec 70 02 00 00 48 8d 6c 24 20 48 8d 0d 41 95 13 00 e8 0b ba ff ff ba 20 00 00 00 48 8d 0d 68 78 12 00 e8 e0 88 ff ff 48 8d 15 d4 18 0f 00 48 8d 8d 50 01 00 00 e8 9b 9c ff ff 90 } //2
		$a_01_1 = {5c 43 6c 69 70 65 7a 5c 78 36 34 5c 44 65 62 75 67 5c 43 6c 69 70 65 7a 2e 70 64 62 } //2 \Clipez\x64\Debug\Clipez.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_Win64_ClipBanker_C_MTB_2{
	meta:
		description = "Trojan:Win64/ClipBanker.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c9 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? b9 01 00 00 00 ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0 0f 84 ?? ?? ?? ?? 48 8b c8 ff 15 ?? ?? ?? ?? 48 85 c0 0f 84 } //3
		$a_01_1 = {30 78 35 38 31 41 36 46 38 38 66 38 37 35 32 32 63 36 39 36 36 32 43 37 35 65 37 36 32 35 33 66 30 36 30 43 35 30 62 31 39 38 } //3 0x581A6F88f87522c69662C75e76253f060C50b198
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //2 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=8
 
}