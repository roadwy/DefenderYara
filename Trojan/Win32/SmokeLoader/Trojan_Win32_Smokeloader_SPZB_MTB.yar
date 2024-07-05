
rule Trojan_Win32_Smokeloader_SPZB_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SPZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {89 45 f8 8b 45 f8 03 45 e0 33 45 e4 33 45 fc 2b d8 89 45 f8 8b c3 c7 05 } //00 00 
	condition:
		any of ($a_*)
 
}