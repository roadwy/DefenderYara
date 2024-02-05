
rule Trojan_Win32_Razy_CI_MTB{
	meta:
		description = "Trojan:Win32/Razy.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {31 0a 09 fe 83 ec 90 01 01 89 34 24 5e 81 c2 90 02 04 39 da 75 e6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}