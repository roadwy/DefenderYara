
rule Trojan_Win32_Zegost_CL_bit{
	meta:
		description = "Trojan:Win32/Zegost.CL!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 45 10 99 b9 fe 00 00 00 f7 f9 89 65 f0 c7 45 e8 00 00 00 00 80 c2 90 01 01 88 55 ef 90 00 } //01 00 
		$a_01_1 = {8b 45 08 8a 10 8a 4d ef 32 d1 02 d1 88 10 } //00 00 
	condition:
		any of ($a_*)
 
}