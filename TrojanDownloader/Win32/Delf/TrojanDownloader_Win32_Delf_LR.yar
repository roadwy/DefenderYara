
rule TrojanDownloader_Win32_Delf_LR{
	meta:
		description = "TrojanDownloader:Win32/Delf.LR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 78 7a 31 39 2e 63 6f 6d } //1 .xz19.com
		$a_01_1 = {2e 68 61 6f 79 65 31 32 33 2e 6e 65 74 } //1 .haoye123.net
		$a_03_2 = {4b 75 6f 44 6f 75 53 65 74 75 70 73 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4b 75 6f 44 6f 75 53 65 74 75 70 73 2e 65 78 65 } //1
		$a_03_3 = {63 6e 69 65 73 65 74 75 70 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 6e 4e 75 6f 49 45 73 2e 74 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 6e 4e 75 6f 49 45 73 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanDownloader_Win32_Delf_LR_2{
	meta:
		description = "TrojanDownloader:Win32/Delf.LR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {d1 eb 0b cb 89 0a 8b 08 33 0a 81 e1 aa aa aa aa } //1
		$a_01_1 = {4d 79 20 44 72 6f 70 62 6f 78 5c 50 72 6f 6a 65 74 6f 73 5c 4a 61 76 61 6e 5c 73 74 61 72 74 5c 70 75 6d 61 6e 65 77 5f 32 5c 70 75 6d 61 78 2e 64 70 72 } //1 My Dropbox\Projetos\Javan\start\pumanew_2\pumax.dpr
		$a_01_2 = {43 41 50 41 2d 43 45 4c 55 4c 41 52 00 00 00 00 55 8b ec } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}