
rule Trojan_Win32_Vundo_HB{
	meta:
		description = "Trojan:Win32/Vundo.HB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 09 e4 cb fc } //01 00 
		$a_01_1 = {bb dd 2c 06 74 } //01 00 
		$a_01_2 = {b9 95 97 56 2a } //01 00 
		$a_01_3 = {81 f1 e4 36 08 58 } //00 00 
	condition:
		any of ($a_*)
 
}