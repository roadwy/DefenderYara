
rule Trojan_Win32_Eqtonex_F{
	meta:
		description = "Trojan:Win32/Eqtonex.F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 c0 40 90 74 08 e8 09 00 00 00 c2 24 00 e8 a7 00 00 00 c3 e8 01 00 00 00 eb 90 5b b9 76 01 00 00 0f 32 a3 fc ff df ff 8d 43 17 31 d2 0f 30 c3 } //01 00 
		$a_01_1 = {48 89 c2 48 c1 ea 20 0f 30 c3 0f 01 f8 65 48 89 24 25 10 00 00 00 65 48 8b 24 25 a8 01 00 00 50 53 51 52 56 57 55 41 50 41 51 41 52 41 53 41 54 } //01 00 
		$a_01_2 = {53 65 48 8b 04 25 38 00 00 00 48 8b 40 04 48 c1 e8 0c 48 c1 e0 0c 48 8b 18 66 81 fb 4d 5a 74 08 48 2d 00 10 00 00 eb ee 5b c3 } //00 00 
	condition:
		any of ($a_*)
 
}