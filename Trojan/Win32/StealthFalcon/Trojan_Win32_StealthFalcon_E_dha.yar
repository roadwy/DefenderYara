
rule Trojan_Win32_StealthFalcon_E_dha{
	meta:
		description = "Trojan:Win32/StealthFalcon.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 44 0e 02 32 44 0e 01 88 04 19 f6 c1 01 75 } //6
		$a_01_1 = {8a 56 02 32 d0 88 14 19 41 3b cf 72 } //6
		$a_01_2 = {8b 45 08 83 f8 01 76 0a 8d 73 01 8d 48 ff 8b fb f3 a4 8b c3 } //6
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*6+(#a_01_2  & 1)*6) >=18
 
}