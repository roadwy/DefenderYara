
rule Trojan_Win32_SmokeLoader_IE_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.IE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 89 1d 90 01 04 8b 45 90 01 01 29 45 90 01 01 81 45 90 01 05 ff 4d 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}