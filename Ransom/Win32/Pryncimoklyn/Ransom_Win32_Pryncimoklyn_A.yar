
rule Ransom_Win32_Pryncimoklyn_A{
	meta:
		description = "Ransom:Win32/Pryncimoklyn.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {36 36 85 c9 74 90 01 01 c1 c0 07 0f b7 c9 8d 52 02 33 c1 0f b7 0a 66 85 c9 75 90 00 } //01 00 
		$a_01_1 = {30 00 30 00 41 00 45 00 25 00 30 00 38 00 58 00 } //01 00  00AE%08X
		$a_00_2 = {2f 73 63 72 69 70 74 73 2f 73 75 70 65 72 66 69 73 68 2f 6a 73 2f 73 75 70 65 72 73 75 62 73 2e 70 68 70 } //01 00  /scripts/superfish/js/supersubs.php
		$a_01_3 = {32 31 32 2e 34 37 2e 32 35 34 2e 31 38 37 } //01 00  212.47.254.187
		$a_00_4 = {25 73 5c 49 4e 53 54 52 55 43 54 49 4f 4e 5f 46 4f 52 5f 48 45 4c 50 49 4e 47 5f 46 49 4c 45 5f 52 45 43 4f 56 45 52 59 2e 54 58 54 } //01 00  %s\INSTRUCTION_FOR_HELPING_FILE_RECOVERY.TXT
		$a_00_5 = {25 00 73 00 25 00 30 00 38 00 58 00 25 00 30 00 38 00 58 00 25 00 30 00 38 00 58 00 25 00 30 00 38 00 58 00 2e 00 } //01 00  %s%08X%08X%08X%08X.
		$a_00_6 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 4e 6f } //00 00  bcdedit /set {default} recoveryenabled No
		$a_00_7 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}