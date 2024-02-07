
rule TrojanDownloader_Win32_Delf_IU{
	meta:
		description = "TrojanDownloader:Win32/Delf.IU,SIGNATURE_TYPE_PEHSTR,20 00 20 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {4e 00 54 00 6b 00 72 00 6e 00 6c 00 20 00 53 00 65 00 63 00 75 00 72 00 65 00 20 00 53 00 75 00 69 00 74 00 65 00 } //0a 00  NTkrnl Secure Suite
		$a_01_2 = {65 64 73 6f 6e 7a 75 61 6e 64 6f 74 75 64 6f 2e 69 6e 66 6f 2f 32 30 } //01 00  edsonzuandotudo.info/20
		$a_01_3 = {73 65 6e 74 30 30 39 2e 68 70 67 2e 63 6f 6d 2e 62 72 2f 68 75 6e 74 65 72 2e 6a 70 67 } //01 00  sent009.hpg.com.br/hunter.jpg
		$a_01_4 = {73 65 6e 74 30 30 39 2e 68 70 67 2e 63 6f 6d 2e 62 72 2f 77 69 6c 6c 6b 69 6c 6c 2e 6a 70 67 } //01 00  sent009.hpg.com.br/willkill.jpg
		$a_01_5 = {73 65 6e 74 30 30 39 2e 68 70 67 2e 63 6f 6d 2e 62 72 2f 6d 73 6e 6c 6f 67 65 2e 6a 70 67 } //01 00  sent009.hpg.com.br/msnloge.jpg
		$a_01_6 = {73 65 6e 74 30 30 39 2e 68 70 67 2e 63 6f 6d 2e 62 72 2f 6d 73 6e 73 65 6e 64 2e 6a 70 67 } //00 00  sent009.hpg.com.br/msnsend.jpg
	condition:
		any of ($a_*)
 
}