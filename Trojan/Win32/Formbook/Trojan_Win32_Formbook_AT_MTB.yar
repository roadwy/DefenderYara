
rule Trojan_Win32_Formbook_AT_MTB{
	meta:
		description = "Trojan:Win32/Formbook.AT!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {56 8b 75 08 2b f0 8a 10 49 88 14 06 40 85 c9 7f f5 } //0a 00 
		$a_01_1 = {8b 4d fc 8a 04 39 03 cf 88 45 f4 8d 50 c0 80 fa 1f 77 18 } //00 00 
	condition:
		any of ($a_*)
 
}