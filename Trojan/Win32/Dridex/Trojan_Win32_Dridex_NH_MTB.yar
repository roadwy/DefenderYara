
rule Trojan_Win32_Dridex_NH_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b d2 33 0d 90 01 04 c7 05 90 01 08 8b d1 01 15 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 8b e5 5d c3 90 00 } //01 00 
		$a_02_1 = {8a 0c 31 88 0c 02 8b 15 90 01 04 83 c2 01 89 15 90 01 04 eb 90 09 1d 00 68 90 01 04 ff 15 90 01 04 03 05 90 01 04 8b 15 90 01 04 8b 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}