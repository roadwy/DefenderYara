
rule Trojan_Win32_Razy_CP_MTB{
	meta:
		description = "Trojan:Win32/Razy.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {81 e9 2c b2 5f 08 31 33 43 39 c3 75 e7 } //02 00 
		$a_03_1 = {31 30 40 41 81 c7 90 02 04 39 d8 75 e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}