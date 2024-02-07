
rule Trojan_Win32_Farfli_CU_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 6f 76 65 20 58 4d 54 20 66 6f 72 65 76 65 72 } //01 00  love XMT forever
		$a_01_1 = {43 3a 5c 46 57 2e 62 61 6b } //01 00  C:\FW.bak
		$a_01_2 = {68 74 74 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31 3a 37 37 37 2f 69 70 2e 74 78 74 } //01 00  http://127.0.0.1:777/ip.txt
		$a_01_3 = {68 61 64 65 73 35 32 30 2e 67 6e 77 61 79 2e 6e 65 74 } //01 00  hades520.gnway.net
		$a_01_4 = {53 48 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 50 61 74 68 41 } //01 00  SHGetSpecialFolderPathA
		$a_01_5 = {47 61 6d 65 20 4f 76 65 72 } //00 00  Game Over
	condition:
		any of ($a_*)
 
}