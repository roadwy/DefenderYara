
rule Trojan_Win32_Smokeloader_SPZJ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SPZJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {c7 04 24 f0 43 03 00 83 04 24 0d a1 90 01 04 0f af 04 24 81 3d 90 01 04 9e 13 00 00 a3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}