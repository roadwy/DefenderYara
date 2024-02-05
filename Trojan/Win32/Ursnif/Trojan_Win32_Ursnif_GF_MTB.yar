
rule Trojan_Win32_Ursnif_GF_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 f3 33 b5 90 02 20 2b fe 25 90 02 20 81 6d 90 02 20 bb 90 02 20 81 45 90 02 20 8b 4d 90 01 01 83 25 90 02 20 8b c7 d3 e0 8b cf c1 e9 90 01 01 03 8d 90 02 40 33 c1 8b 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}