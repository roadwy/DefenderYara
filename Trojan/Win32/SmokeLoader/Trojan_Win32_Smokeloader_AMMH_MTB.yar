
rule Trojan_Win32_Smokeloader_AMMH_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.AMMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 4c 24 08 30 0c 1e 83 ff 0f 75 90 01 01 55 55 55 e8 90 01 04 46 3b f7 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}