
rule TrojanDownloader_Win32_Dofoil_AI_bit{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.AI!bit,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 51 8b 34 8a 01 de 89 f0 31 c9 32 28 c1 c1 08 32 cd 40 80 38 00 75 f3 } //2
		$a_01_1 = {8a 1b 32 1e 88 5c 24 04 2a 4c 24 04 33 db 8a d8 03 1c 24 4b 88 0b 47 40 fe ca 75 d3 } //2
		$a_03_2 = {8a d1 0f b6 94 15 ?? ?? ?? ?? 8b f3 81 e6 ff 00 00 00 0f b6 b4 35 ?? ?? ?? ?? 03 d6 81 e2 ff 00 00 00 32 84 15 ?? ?? ?? ?? 8b 55 ?? 8b 75 ?? 88 04 32 } //2
		$a_01_3 = {25 00 73 00 5c 00 25 00 73 00 00 00 25 00 73 00 25 00 73 00 00 00 00 00 72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 20 00 2f 00 73 00 20 00 25 00 73 00 } //1
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}