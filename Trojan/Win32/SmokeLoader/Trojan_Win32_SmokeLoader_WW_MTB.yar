
rule Trojan_Win32_SmokeLoader_WW_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.WW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 ea 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 03 55 90 01 01 03 c7 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 31 55 90 01 01 8b 45 90 01 01 29 45 90 01 01 81 45 ec 90 01 04 ff 4d 90 01 01 89 35 90 01 04 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}