
rule Trojan_Win32_Copak_CW_MTB{
	meta:
		description = "Trojan:Win32/Copak.CW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 3b 81 c3 04 00 00 00 81 ee d9 07 c9 d2 39 cb 75 e9 } //02 00 
		$a_01_1 = {31 31 89 fb 21 fb 81 c1 01 00 00 00 01 fb 29 ff 39 d1 75 d6 } //02 00 
		$a_01_2 = {89 d0 b8 5d c9 ab e3 31 33 09 c2 43 39 cb 75 e0 } //00 00 
	condition:
		any of ($a_*)
 
}