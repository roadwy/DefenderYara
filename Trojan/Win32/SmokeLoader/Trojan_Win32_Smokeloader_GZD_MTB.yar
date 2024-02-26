
rule Trojan_Win32_Smokeloader_GZD_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {6b 00 65 00 c7 05 90 01 04 72 00 6e 00 c7 05 90 01 04 65 00 6c 00 c7 05 90 01 04 33 00 32 00 c7 05 90 01 04 2e 00 64 00 c7 05 90 01 04 6c 00 6c 00 66 a3 90 01 04 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}