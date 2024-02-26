
rule Trojan_Win32_RiseProStealer_YAB_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {70 5a 37 59 8b 45 d8 8b 4d dc c5 fe 6f 85 90 01 04 89 85 90 01 04 8d 85 90 01 04 89 8d 90 01 04 c5 fd ef 85 90 01 04 50 c5 fd 7f 85 90 01 04 57 c5 f8 77 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}