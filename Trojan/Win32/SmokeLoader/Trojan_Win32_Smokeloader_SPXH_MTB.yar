
rule Trojan_Win32_Smokeloader_SPXH_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SPXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 31 45 f0 8b 45 f0 31 45 f8 2b 75 f8 } //00 00 
	condition:
		any of ($a_*)
 
}