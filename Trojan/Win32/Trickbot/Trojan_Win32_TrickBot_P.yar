
rule Trojan_Win32_TrickBot_P{
	meta:
		description = "Trojan:Win32/TrickBot.P,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 7c 24 0c 90 02 01 90 01 08 8b 54 24 18 85 d2 74 90 01 01 ac 52 30 07 5a 4a 47 e2 f3 5e 5b 33 c0 c3 90 00 } //01 00 
		$a_01_1 = {48 89 58 10 48 89 70 18 49 8b d9 49 8b f8 48 8b f2 b9 30 00 00 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}