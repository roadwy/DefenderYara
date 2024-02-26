
rule Trojan_Win64_Keylogger_RR_MTB{
	meta:
		description = "Trojan:Win64/Keylogger.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 46 44 4b 5c 41 46 44 4b 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 41 46 44 4b 2e 70 64 62 } //01 00  AFDK\AFDK\x64\Release\AFDK.pdb
		$a_01_1 = {33 33 30 31 4b 69 72 61 } //05 00  3301Kira
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 64 00 65 00 66 00 39 00 62 00 36 00 63 00 64 00 33 00 66 00 32 00 62 00 30 00 63 00 34 00 33 00 30 00 39 00 37 00 64 00 66 00 62 00 63 00 39 00 31 00 38 00 38 00 36 00 32 00 62 00 38 00 32 00 } //00 00  Software\def9b6cd3f2b0c43097dfbc918862b82
	condition:
		any of ($a_*)
 
}