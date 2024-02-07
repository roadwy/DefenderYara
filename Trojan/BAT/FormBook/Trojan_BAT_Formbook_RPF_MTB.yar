
rule Trojan_BAT_Formbook_RPF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //01 00  cdn.discordapp.com
		$a_01_1 = {41 00 6f 00 79 00 6b 00 6a 00 5f 00 34 00 32 00 31 00 38 00 30 00 5f 00 2e 00 62 00 6d 00 70 00 } //01 00  Aoykj_42180_.bmp
		$a_01_2 = {4d 00 74 00 76 00 6e 00 67 00 77 00 79 00 75 00 } //01 00  Mtvngwyu
		$a_01_3 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //01 00  powershell
		$a_01_4 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //01 00  get_Assembly
		$a_01_5 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_6 = {52 65 61 64 42 79 74 65 73 } //01 00  ReadBytes
		$a_01_7 = {57 65 62 52 65 71 75 65 73 74 } //00 00  WebRequest
	condition:
		any of ($a_*)
 
}