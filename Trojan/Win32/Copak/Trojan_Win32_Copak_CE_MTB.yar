
rule Trojan_Win32_Copak_CE_MTB{
	meta:
		description = "Trojan:Win32/Copak.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {31 17 01 c0 47 81 c0 90 02 04 39 cf 75 e5 90 00 } //02 00 
		$a_03_1 = {31 16 46 b8 90 02 04 39 fe 75 da 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}