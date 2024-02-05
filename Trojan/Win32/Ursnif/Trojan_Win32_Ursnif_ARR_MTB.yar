
rule Trojan_Win32_Ursnif_ARR_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {40 0f af c3 ff 4c 24 90 01 01 0f b7 c0 0f b7 d8 8d b4 19 90 01 04 0f 85 90 0a 48 00 8b 44 24 90 01 01 8b 4c 24 90 01 01 83 44 24 90 01 02 81 c5 b4 9d d8 01 89 28 8b 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}