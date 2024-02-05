
rule Trojan_Win64_BumbleBee_MAT_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.MAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 8b c9 41 8b d2 d3 ea 8a 88 90 01 04 48 8b 43 90 01 01 80 f1 1c 22 d1 48 63 8b 04 01 00 00 88 14 01 48 c7 c0 90 01 04 ff 83 90 01 04 48 2b 83 90 01 04 48 01 83 90 01 04 45 85 c9 75 90 01 01 48 8b 83 90 01 04 49 83 c0 04 48 0d 90 01 04 48 89 83 90 01 04 49 81 f8 90 01 04 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}