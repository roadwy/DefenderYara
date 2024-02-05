
rule Trojan_Win32_Zbot_KA_MTB{
	meta:
		description = "Trojan:Win32/Zbot.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {89 d9 29 c9 31 32 43 89 d9 81 c3 01 00 00 00 81 c2 02 00 00 00 01 c9 39 c2 7c d8 } //01 00 
		$a_03_1 = {8a 19 29 ff 81 c7 90 01 04 42 88 1e 47 46 81 ef 01 00 00 00 21 d7 81 c1 02 00 00 00 21 ff 39 c1 7e dd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}