
rule Trojan_Win32_Cridex_MA_MTB{
	meta:
		description = "Trojan:Win32/Cridex.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {8a 4c 24 6a 30 c9 88 8c 24 c7 00 00 00 8b 94 24 c0 00 00 00 8a 4c 24 6a 00 c9 88 8c 24 c7 00 00 00 81 c2 29 be 0c 36 89 84 24 84 00 00 00 89 94 24 a8 00 00 00 81 bc 24 a8 00 00 00 9f 5c dd 49 0f 83 } //05 00 
		$a_01_1 = {0d 83 b2 77 49 e2 dc 24 49 e2 dc 24 49 e2 dc 24 d2 09 12 24 80 e3 dc 24 57 b0 5f 24 3e e2 dc 24 49 e2 dd 24 7c e2 dc 24 de } //00 00 
	condition:
		any of ($a_*)
 
}