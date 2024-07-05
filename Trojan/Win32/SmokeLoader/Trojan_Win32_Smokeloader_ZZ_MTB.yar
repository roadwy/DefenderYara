
rule Trojan_Win32_Smokeloader_ZZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.ZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 33 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 29 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}