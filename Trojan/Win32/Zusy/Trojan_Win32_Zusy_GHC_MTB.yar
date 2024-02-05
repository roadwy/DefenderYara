
rule Trojan_Win32_Zusy_GHC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 34 24 83 c4 04 e8 90 01 04 31 33 89 c0 89 f8 43 39 d3 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}