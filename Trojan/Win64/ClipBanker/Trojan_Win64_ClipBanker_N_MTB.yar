
rule Trojan_Win64_ClipBanker_N_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 09 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 55 70 64 61 74 65 2e 65 78 65 } //02 00  \Microsoft\Windows\Start Menu\Programs\Startup\Update.exe
		$a_01_1 = {4c 4f 43 41 4c 41 50 50 44 41 54 41 } //02 00  LOCALAPPDATA
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //02 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {28 62 63 31 7c 5b 31 33 5d 29 5b 61 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 30 2d 39 5d 7b 32 35 2c 33 39 7d 24 } //02 00  (bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$
		$a_01_4 = {30 78 5b 61 2d 66 41 2d 46 30 2d 39 5d 7b 34 30 7d 24 } //02 00  0x[a-fA-F0-9]{40}$
		$a_01_5 = {5b 4c 4d 5d 5b 61 2d 6b 6d 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 31 2d 39 5d 7b 32 36 2c 33 33 7d 24 } //02 00  [LM][a-km-zA-HJ-NP-Z1-9]{26,33}$
		$a_01_6 = {5b 34 7c 38 5d 28 5b 30 2d 39 5d 7c 5b 41 2d 42 5d 29 28 2e 29 7b 39 33 7d } //02 00  [4|8]([0-9]|[A-B])(.){93}
		$a_01_7 = {54 5b 41 2d 5a 61 2d 7a 31 2d 39 5d 7b 33 33 7d } //01 00  T[A-Za-z1-9]{33}
		$a_01_8 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //00 00  SetClipboardData
	condition:
		any of ($a_*)
 
}