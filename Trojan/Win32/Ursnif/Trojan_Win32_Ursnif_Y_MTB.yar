
rule Trojan_Win32_Ursnif_Y_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {d3 c0 83 f3 90 01 01 89 02 83 c2 90 00 } //02 00 
		$a_03_1 = {d3 e0 83 c7 90 01 01 03 d8 4e 85 f6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}