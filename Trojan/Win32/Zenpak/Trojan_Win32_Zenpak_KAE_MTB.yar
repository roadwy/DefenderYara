
rule Trojan_Win32_Zenpak_KAE_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 3f 8b 12 0f b7 1b 31 fb 89 34 24 } //00 00 
	condition:
		any of ($a_*)
 
}