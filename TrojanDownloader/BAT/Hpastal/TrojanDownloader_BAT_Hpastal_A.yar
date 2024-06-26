
rule TrojanDownloader_BAT_Hpastal_A{
	meta:
		description = "TrojanDownloader:BAT/Hpastal.A,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 56 69 72 74 75 61 6c 42 6f 78 } //01 00  AntiVirtualBox
		$a_01_1 = {41 6e 74 69 57 69 72 65 73 68 61 72 6b } //01 00  AntiWireshark
		$a_01_2 = {41 6e 74 69 4f 6c 6c 79 64 62 67 } //01 00  AntiOllydbg
		$a_01_3 = {41 6e 74 69 4b 61 73 70 65 72 73 6b 79 } //01 00  AntiKaspersky
		$a_01_4 = {41 6e 74 69 56 69 72 74 75 61 6c 50 43 } //01 00  AntiVirtualPC
		$a_01_5 = {43 00 68 00 72 00 6f 00 6d 00 65 00 50 00 61 00 73 00 73 00 2e 00 74 00 78 00 74 00 } //01 00  ChromePass.txt
		$a_01_6 = {66 00 6f 00 78 00 70 00 61 00 73 00 73 00 2e 00 74 00 78 00 74 00 } //01 00  foxpass.txt
		$a_01_7 = {6f 00 70 00 65 00 72 00 61 00 70 00 61 00 73 00 73 00 2e 00 74 00 78 00 74 00 } //01 00  operapass.txt
		$a_01_8 = {69 00 65 00 70 00 61 00 73 00 73 00 2e 00 74 00 78 00 74 00 } //01 00  iepass.txt
		$a_01_9 = {6d 00 73 00 6e 00 70 00 61 00 73 00 73 00 2e 00 74 00 78 00 74 00 } //0a 00  msnpass.txt
		$a_01_10 = {7c 00 73 00 70 00 6c 00 69 00 74 00 7c 00 } //0a 00  |split|
		$a_01_11 = {7a 00 6c 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //00 00  zlclient
		$a_00_12 = {5d 04 00 00 81 16 03 80 5c 21 00 00 82 16 03 80 00 00 01 00 28 } //00 0b 
	condition:
		any of ($a_*)
 
}