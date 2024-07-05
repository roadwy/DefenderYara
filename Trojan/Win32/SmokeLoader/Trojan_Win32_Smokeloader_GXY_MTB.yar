
rule Trojan_Win32_Smokeloader_GXY_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {30 0c 1e 83 ff 0f 90 01 02 6a 00 6a 00 ff 15 90 01 04 6a 00 6a 00 6a 00 6a 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}