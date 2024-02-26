
rule Trojan_Win64_Keylogger_RB_MTB{
	meta:
		description = "Trojan:Win64/Keylogger.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {33 33 30 31 4b 69 72 61 } //05 00  3301Kira
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 64 00 65 00 66 00 39 00 62 00 36 00 63 00 64 00 33 00 66 00 32 00 62 00 30 00 63 00 34 00 33 00 30 00 39 00 37 00 64 00 66 00 62 00 63 00 39 00 31 00 38 00 38 00 36 00 32 00 62 00 38 00 32 00 } //01 00  Software\def9b6cd3f2b0c43097dfbc918862b82
		$a_01_2 = {6b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 73 00 61 00 76 00 65 00 20 00 4f 00 4b 00 } //01 00  keylogger save OK
		$a_01_3 = {4b 65 79 6c 6f 67 67 65 72 20 69 73 20 75 70 20 61 6e 64 20 72 75 6e 6e 69 6e 67 } //00 00  Keylogger is up and running
	condition:
		any of ($a_*)
 
}