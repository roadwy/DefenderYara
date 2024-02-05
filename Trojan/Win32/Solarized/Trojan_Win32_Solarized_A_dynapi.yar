
rule Trojan_Win32_Solarized_A_dynapi{
	meta:
		description = "Trojan:Win32/Solarized.A!dynapi,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0d f1 28 0b 04 46 e3 6b 0e 46 90 01 02 13 eb 00 09 90 01 02 d9 f8 74 30 00 2b 90 01 02 d9 f8 78 30 00 2b 90 00 } //01 00 
		$a_01_1 = {b9 68 40 23 4f f4 40 52 00 20 a8 47 23 68 05 46 } //01 00 
		$a_01_2 = {eb 6b 17 f1 08 01 17 f1 10 00 2b 44 9b 6a 2b 44 bb 60 } //00 00 
	condition:
		any of ($a_*)
 
}