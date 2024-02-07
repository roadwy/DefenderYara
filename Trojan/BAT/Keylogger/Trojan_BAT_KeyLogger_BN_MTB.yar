
rule Trojan_BAT_KeyLogger_BN_MTB{
	meta:
		description = "Trojan:BAT/KeyLogger.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 00 73 00 61 00 31 00 39 00 39 00 37 00 40 00 6f 00 32 00 2e 00 70 00 6c 00 } //01 00  dsa1997@o2.pl
		$a_01_1 = {74 00 65 00 73 00 74 00 69 00 6e 00 67 00 5f 00 6b 00 6c 00 } //01 00  testing_kl
		$a_01_2 = {74 00 65 00 73 00 74 00 69 00 6e 00 67 00 6b 00 6c 00 40 00 79 00 61 00 68 00 6f 00 6f 00 2e 00 63 00 6f 00 6d 00 } //01 00  testingkl@yahoo.com
		$a_01_3 = {68 6f 6f 6b 5f 4b 65 79 50 72 65 73 73 65 64 } //01 00  hook_KeyPressed
		$a_01_4 = {5b 00 46 00 31 00 32 00 5d 00 } //01 00  [F12]
		$a_01_5 = {50 41 53 53 57 4f 52 44 } //01 00  PASSWORD
		$a_01_6 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //01 00  Form1_Load
		$a_01_7 = {5b 00 43 00 41 00 50 00 53 00 4c 00 4f 00 43 00 4b 00 5d 00 } //01 00  [CAPSLOCK]
		$a_01_8 = {5b 00 52 00 5f 00 43 00 54 00 52 00 4c 00 5d 00 } //01 00  [R_CTRL]
		$a_01_9 = {5b 00 50 00 52 00 49 00 4e 00 54 00 53 00 43 00 52 00 45 00 45 00 4e 00 5d 00 } //01 00  [PRINTSCREEN]
		$a_01_10 = {5b 00 57 00 49 00 4e 00 5d 00 } //01 00  [WIN]
		$a_01_11 = {4e 65 74 77 6f 72 6b 43 72 65 64 65 6e 74 69 61 6c } //01 00  NetworkCredential
		$a_01_12 = {6b 65 79 62 6f 61 72 64 48 6f 6f 6b 50 72 6f 63 } //01 00  keyboardHookProc
		$a_01_13 = {41 70 70 65 6e 64 } //00 00  Append
	condition:
		any of ($a_*)
 
}