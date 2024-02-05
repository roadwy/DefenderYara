
rule Trojan_Win32_ClipBanker_RT_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 d2 8b f8 59 8b f2 8a 0c 75 90 01 04 88 0c 3e 46 3b f3 72 90 01 01 8b c2 83 e0 0f 8a 80 90 01 04 30 04 3a 42 3b d3 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_ClipBanker_RT_MTB_2{
	meta:
		description = "Trojan:Win32/ClipBanker.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 9b 01 00 00 85 c0 74 90 01 01 8b 0d 90 01 04 3b 0d 90 01 04 72 90 01 01 eb 90 01 01 68 90 01 04 ff 15 90 01 04 03 05 90 01 04 8b 15 90 01 04 03 15 90 01 04 8b 0d 90 01 04 8a 04 01 88 02 8b 0d 90 01 04 83 c1 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}