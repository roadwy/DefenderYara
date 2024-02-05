
rule Trojan_Win64_Bumblebee_WKX_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.WKX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 8b d0 b8 01 00 00 00 c1 ea 08 2b 83 90 01 04 01 83 90 01 04 8b 43 90 01 01 01 43 90 01 01 8b 43 90 01 01 8b 8b 90 01 04 ff c1 0f af c1 89 43 90 01 01 48 63 4b 90 01 01 48 8b 83 90 01 04 88 14 01 ff 43 90 01 01 48 63 4b 90 01 01 48 8b 83 90 01 04 44 88 04 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}