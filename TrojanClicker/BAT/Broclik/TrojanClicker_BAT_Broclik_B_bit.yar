
rule TrojanClicker_BAT_Broclik_B_bit{
	meta:
		description = "TrojanClicker:BAT/Broclik.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_03_1 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5f 00 [0-10] 61 00 6c 00 6c 00 75 00 73 00 65 00 72 00 73 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 } //1
		$a_01_2 = {66 00 79 00 6a 00 46 00 52 00 52 00 52 00 52 00 52 00 } //1 fyjFRRRRR
		$a_03_3 = {58 00 58 00 58 00 58 00 30 00 3a 00 [0-10] 58 00 58 00 58 00 58 00 31 00 3a 00 [0-10] 58 00 58 00 58 00 58 00 32 00 3a 00 [0-10] 58 00 58 00 58 00 58 00 33 00 3a 00 [0-10] 58 00 58 00 58 00 58 00 34 00 3a 00 } //1
		$a_01_4 = {28 00 28 00 28 00 66 00 7c 00 58 00 58 00 29 00 7b 00 31 00 7d 00 58 00 58 00 29 00 } //1 (((f|XX){1}XX)
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}