
rule Trojan_Win64_AsyncRat_ASC_MTB{
	meta:
		description = "Trojan:Win64/AsyncRat.ASC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 98 48 8b 95 a8 04 00 00 48 01 d0 0f b6 00 32 85 a7 04 00 00 48 8b 8d 90 04 00 00 8b 95 bc 04 00 00 48 63 d2 88 04 11 83 85 bc 04 00 00 01 8b 95 bc 04 00 00 8b 85 5c 04 00 00 39 c2 } //5
		$a_01_1 = {4d 89 c1 49 89 c8 48 89 c1 48 8b 05 5a 6b 00 00 ff d0 48 8b 85 78 04 00 00 48 8d 50 30 48 8b 85 70 04 00 00 48 8b 80 88 00 00 00 48 83 c0 10 48 89 c1 48 8b 85 40 04 00 00 48 c7 44 24 20 00 00 00 00 41 b9 08 00 00 00 49 89 d0 48 89 ca 48 89 c1 } //3
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3) >=8
 
}
rule Trojan_Win64_AsyncRat_ASC_MTB_2{
	meta:
		description = "Trojan:Win64/AsyncRat.ASC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 28 48 8d 15 f5 44 00 00 48 8d 0d f6 78 00 00 e8 ?? ?? ?? ?? 48 8d 0d 32 34 00 00 48 83 c4 28 } //5
		$a_01_1 = {73 65 66 74 61 6c 69 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 73 65 66 74 61 6c 69 2e 70 64 62 } //2 seftali\x64\Release\seftali.pdb
		$a_01_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 67 00 69 00 74 00 68 00 75 00 62 00 2e 00 63 00 6f 00 6d 00 2f 00 65 00 72 00 72 00 69 00 61 00 73 00 2f 00 58 00 57 00 6f 00 72 00 6d 00 2d 00 52 00 61 00 74 00 2d 00 52 00 65 00 6d 00 6f 00 74 00 65 00 2d 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2d 00 54 00 6f 00 6f 00 6c 00 2d 00 2f 00 72 00 61 00 77 00 2f 00 6d 00 61 00 69 00 6e 00 2f 00 58 00 57 00 6f 00 72 00 6d 00 55 00 49 00 2e 00 65 00 78 00 65 00 } //3 https://github.com/errias/XWorm-Rat-Remote-Administration-Tool-/raw/main/XWormUI.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3) >=10
 
}