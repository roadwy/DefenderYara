
rule Trojan_Win32_Fenibot_A{
	meta:
		description = "Trojan:Win32/Fenibot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 21 62 6f 74 6b 69 6c 6c 65 72 00 } //01 00 
		$a_01_1 = {46 58 44 44 6f 53 00 } //01 00 
		$a_01_2 = {00 4e 6f 20 46 54 50 20 41 63 63 6f 75 6e 74 73 20 46 6f 75 6e 64 2e 00 } //00 00 
	condition:
		any of ($a_*)
 
}