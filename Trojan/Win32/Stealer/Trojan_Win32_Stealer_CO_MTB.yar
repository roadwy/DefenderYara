
rule Trojan_Win32_Stealer_CO_MTB{
	meta:
		description = "Trojan:Win32/Stealer.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {2a 14 eb 03 e9 5b 30 b8 90 02 04 eb 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}