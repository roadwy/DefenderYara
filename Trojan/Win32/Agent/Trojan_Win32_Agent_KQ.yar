
rule Trojan_Win32_Agent_KQ{
	meta:
		description = "Trojan:Win32/Agent.KQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 61 00 72 00 6c 00 6f 00 73 00 } //01 00  carlos
		$a_01_1 = {4c 52 41 43 4d 31 00 00 4c 52 41 43 31 } //01 00 
		$a_01_2 = {68 fc 2e 40 00 a1 14 41 40 00 50 ff d7 8b f0 6a 0a 68 04 2f 40 00 a1 04 41 40 00 50 ff d7 } //00 00 
	condition:
		any of ($a_*)
 
}