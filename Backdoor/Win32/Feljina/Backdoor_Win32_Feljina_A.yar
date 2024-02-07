
rule Backdoor_Win32_Feljina_A{
	meta:
		description = "Backdoor:Win32/Feljina.A,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 13 00 00 08 00 "
		
	strings :
		$a_03_0 = {01 00 83 c4 0c c6 45 ec a2 c6 45 ed 13 c6 45 ee 90 01 01 c6 45 ef 90 00 } //04 00 
		$a_01_1 = {6c 72 3a 25 64 2c 25 64 2c 25 64 3b 6c 61 3a 25 64 2c 25 64 2c 25 64 3b 63 72 3a 25 64 2c 25 64 2c 25 64 } //04 00  lr:%d,%d,%d;la:%d,%d,%d;cr:%d,%d,%d
		$a_01_2 = {25 64 2c 25 64 2c 25 64 2c 78 78 3a 25 64 6b 6b 3a 30 78 25 78 } //02 00  %d,%d,%d,xx:%dkk:0x%x
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 47 6f 6c 64 65 6e 4b 65 79 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\GoldenKey
		$a_01_4 = {61 6e 73 5f 77 6f 72 6b } //01 00  ans_work
		$a_01_5 = {47 65 74 48 74 6f 53 } //01 00  GetHtoS
		$a_01_6 = {47 65 74 53 5f 50 55 42 4b 45 59 } //01 00  GetS_PUBKEY
		$a_01_7 = {49 44 6e 6f 74 45 51 55 } //01 00  IDnotEQU
		$a_01_8 = {6a 69 61 6e 6a 69 6e 65 } //01 00  jianjine
		$a_01_9 = {6e 65 77 6a 69 61 6e 6a 69 6e 65 } //01 00  newjianjine
		$a_01_10 = {53 65 6e 64 5f 53 5f 54 6f 5f 48 } //01 00  Send_S_To_H
		$a_01_11 = {72 65 61 64 73 65 74 5f 69 6e 66 6f } //01 00  readset_info
		$a_01_12 = {54 65 73 74 63 61 72 64 6f 6e } //01 00  Testcardon
		$a_01_13 = {61 73 6b 5f 77 6f 72 6b } //01 00  ask_work
		$a_01_14 = {62 61 63 6b 48 61 72 64 5f 69 6e 66 6f } //01 00  backHard_info
		$a_01_15 = {65 78 65 79 65 6a 69 } //01 00  exeyeji
		$a_01_16 = {6e 65 77 5f 65 78 65 79 65 6a 69 } //01 00  new_exeyeji
		$a_01_17 = {73 65 74 6a 69 68 61 6f } //01 00  setjihao
		$a_01_18 = {74 6d 70 73 68 61 6e 67 6a 69 } //00 00  tmpshangji
	condition:
		any of ($a_*)
 
}