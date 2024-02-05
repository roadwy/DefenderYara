
rule Trojan_Win32_Dridex_NA_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 08 5d c3 90 0a 25 00 33 90 02 05 c7 05 90 02 08 01 15 90 02 04 a1 90 02 04 8b 90 00 } //01 00 
		$a_02_1 = {83 c2 01 89 90 02 05 eb 90 09 24 00 ff 90 02 05 03 90 02 05 8b 90 02 05 8b 90 02 05 8a 90 02 03 88 90 02 03 8b 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}