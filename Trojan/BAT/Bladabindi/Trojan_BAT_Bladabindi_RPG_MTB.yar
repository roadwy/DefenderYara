
rule Trojan_BAT_Bladabindi_RPG_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 00 6e 00 69 00 6f 00 6e 00 2e 00 77 00 73 00 2f 00 71 00 75 00 61 00 63 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  onion.ws/quace.exe
		$a_01_1 = {41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 4e 00 76 00 69 00 64 00 69 00 61 00 47 00 65 00 66 00 72 00 6f 00 63 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  AppData\Local\NvidiaGefroce.exe
		$a_01_2 = {72 00 75 00 6e 00 61 00 73 00 } //01 00  runas
		$a_01_3 = {57 65 62 43 6c 69 65 6e 74 } //01 00  WebClient
		$a_01_4 = {43 6f 6e 63 61 74 } //01 00  Concat
		$a_01_5 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_6 = {52 61 6d 62 6f } //01 00  Rambo
		$a_01_7 = {4d 61 79 6f 6e 6e 61 69 73 65 } //00 00  Mayonnaise
	condition:
		any of ($a_*)
 
}