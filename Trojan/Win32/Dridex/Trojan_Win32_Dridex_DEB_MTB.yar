
rule Trojan_Win32_Dridex_DEB_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c3 2b c1 8b d5 2b d6 8d 54 13 ff 8b 1d 90 01 04 83 c0 50 03 d8 89 15 90 01 04 8b 17 8d b4 0e 90 01 04 8d 8c 19 90 01 04 81 c2 90 01 04 8b c1 2b c5 89 17 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}