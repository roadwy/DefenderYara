
rule Trojan_Win32_Tnega_AE_MTB{
	meta:
		description = "Trojan:Win32/Tnega.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 d6 81 f6 90 02 04 c1 e6 04 81 c6 90 02 04 01 f7 5e 81 c7 90 02 04 81 eb 90 02 04 01 fb 81 c3 90 02 04 5f e9 90 00 } //01 00 
		$a_01_1 = {89 e7 81 c7 04 00 00 00 81 ef 04 00 00 00 33 3c 24 31 3c 24 33 3c 24 5c 89 2c 24 } //00 00 
	condition:
		any of ($a_*)
 
}