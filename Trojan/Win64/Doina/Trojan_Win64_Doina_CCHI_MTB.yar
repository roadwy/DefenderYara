
rule Trojan_Win64_Doina_CCHI_MTB{
	meta:
		description = "Trojan:Win64/Doina.CCHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 6f 75 74 70 75 74 } //01 00  /output
		$a_01_1 = {2f 4c 6f 67 69 6e 20 44 61 74 61 } //01 00  /Login Data
		$a_01_2 = {2f 48 69 73 74 6f 72 79 } //01 00  /History
		$a_01_3 = {2f 57 65 62 20 44 61 74 61 } //01 00  /Web Data
		$a_01_4 = {2f 6e 65 74 77 6f 72 6b 2f 63 6f 6f 6b 69 65 73 } //01 00  /network/cookies
		$a_01_5 = {2f 6c 6f 67 69 6e 64 61 74 61 } //01 00  /logindata
		$a_01_6 = {2f 77 65 62 64 61 74 61 } //01 00  /webdata
		$a_01_7 = {2f 63 6f 6f 6b 69 65 } //01 00  /cookie
		$a_01_8 = {2f 73 65 73 73 69 6f 6e } //01 00  /session
		$a_01_9 = {2f 6c 6f 67 } //01 00  /log
		$a_01_10 = {2f 61 75 74 6f 66 69 6c 6c } //01 00  /autofill
		$a_01_11 = {63 68 61 74 5f 69 64 } //01 00  chat_id
		$a_01_12 = {2f 73 65 6e 64 44 6f 63 75 6d 65 6e 74 } //00 00  /sendDocument
	condition:
		any of ($a_*)
 
}