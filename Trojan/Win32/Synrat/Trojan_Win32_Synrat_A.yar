
rule Trojan_Win32_Synrat_A{
	meta:
		description = "Trojan:Win32/Synrat.A,SIGNATURE_TYPE_PEHSTR,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 79 6e 52 61 74 20 32 2e 31 } //01 00  SynRat 2.1
		$a_01_1 = {44 61 72 6b 43 6f 64 65 72 53 63 } //01 00  DarkCoderSc
		$a_01_2 = {57 61 79 74 69 6e 67 20 66 6f 72 20 73 65 72 76 65 72 } //01 00  Wayting for server
		$a_01_3 = {53 65 72 76 65 72 20 43 6f 6e 6e 65 63 74 65 64 20 74 6f 20 53 69 6e 20 43 6c 69 65 6e 74 } //00 00  Server Connected to Sin Client
	condition:
		any of ($a_*)
 
}