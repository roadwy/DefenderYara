
rule Trojan_Win32_SmokeLoader_GCJ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e0 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 03 c6 89 45 90 01 01 8b c6 d3 e8 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 89 1d 90 01 04 8b 45 90 01 01 29 45 90 01 01 8d 45 90 01 01 e8 90 01 04 ff 4d 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}