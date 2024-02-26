
rule Trojan_Win32_SmokeLoader_RDS_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 8d f8 f7 ff ff 30 04 39 83 fb 0f 75 1e } //00 00 
	condition:
		any of ($a_*)
 
}