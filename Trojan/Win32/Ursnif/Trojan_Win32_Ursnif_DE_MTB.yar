
rule Trojan_Win32_Ursnif_DE_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 cb 8b c1 0f af 05 90 01 04 a3 90 01 04 8d 04 11 8d 04 45 4a 00 00 00 a3 90 01 04 8d 04 32 81 c5 34 b2 08 01 66 03 d8 89 2d 90 01 04 8b 44 24 14 66 89 1d 90 01 04 89 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}