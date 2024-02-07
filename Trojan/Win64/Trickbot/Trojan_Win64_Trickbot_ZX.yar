
rule Trojan_Win64_Trickbot_ZX{
	meta:
		description = "Trojan:Win64/Trickbot.ZX,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 41 49 4c 45 44 20 74 6f 20 73 65 6e 64 20 50 41 53 53 57 4f 52 44 53 20 74 6f 20 44 50 6f 73 74 } //01 00  FAILED to send PASSWORDS to DPost
		$a_01_1 = {44 50 53 54 } //01 00  DPST
		$a_01_2 = {46 41 49 4c 45 44 20 74 6f 20 73 65 6e 64 20 48 49 53 54 4f 52 59 20 74 6f 20 44 50 6f 73 74 } //01 00  FAILED to send HISTORY to DPost
		$a_01_3 = {46 41 49 4c 45 44 20 74 6f 20 73 65 6e 64 20 61 75 74 6f 66 69 6c 6c 20 64 61 74 61 20 74 6f 20 44 50 6f 73 74 } //01 00  FAILED to send autofill data to DPost
		$a_01_4 = {46 41 49 4c 45 44 20 74 6f 20 73 65 6e 64 20 48 54 54 50 20 50 4f 53 54 20 69 6e 74 65 72 63 65 70 74 20 74 6f 20 44 50 6f 73 74 } //01 00  FAILED to send HTTP POST intercept to DPost
		$a_01_5 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 73 65 6e 74 20 50 41 53 53 57 4f 52 44 53 20 74 6f 20 44 50 6f 73 74 } //01 00  Successfully sent PASSWORDS to DPost
		$a_01_6 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 73 65 6e 74 20 48 49 53 54 4f 52 59 20 74 6f 20 44 50 6f 73 74 } //01 00  Successfully sent HISTORY to DPost
		$a_01_7 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 73 65 6e 74 20 61 75 74 6f 66 69 6c 6c 20 64 61 74 61 20 74 6f 20 44 50 6f 73 74 } //00 00  Successfully sent autofill data to DPost
	condition:
		any of ($a_*)
 
}