
rule Trojan_Win32_Stealc_KAC_MTB{
	meta:
		description = "Trojan:Win32/Stealc.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 33 c6 89 45 90 01 01 2b f8 8d 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}