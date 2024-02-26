
rule Trojan_Win32_Smokeloader_SPGS_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SPGS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {31 45 f0 8b 45 f0 33 c2 2b f0 } //00 00 
	condition:
		any of ($a_*)
 
}