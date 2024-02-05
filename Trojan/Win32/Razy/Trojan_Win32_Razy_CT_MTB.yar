
rule Trojan_Win32_Razy_CT_MTB{
	meta:
		description = "Trojan:Win32/Razy.CT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {be 12 67 b4 32 e9 90 02 04 31 34 81 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}