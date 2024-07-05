
rule Trojan_Win32_Copak_GPL_MTB{
	meta:
		description = "Trojan:Win32/Copak.GPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 04 00 "
		
	strings :
		$a_03_0 = {b8 d8 85 40 00 81 90 02 50 81 e0 ff 00 00 00 90 00 } //04 00 
		$a_03_1 = {b8 d8 85 40 00 57 90 02 50 81 e0 ff 00 00 00 90 00 } //04 00 
		$a_03_2 = {ba d8 85 40 00 83 90 02 50 81 e2 ff 00 00 00 90 00 } //04 00 
		$a_03_3 = {68 d8 85 40 00 5f 90 02 50 81 e7 ff 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}