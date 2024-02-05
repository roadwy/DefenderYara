
rule Trojan_Win32_Ursnif_DB_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 d0 2b d1 8b 0d 90 01 04 83 c1 63 03 ca 89 0d 90 01 04 81 c6 38 84 0b 01 0f b6 c8 89 35 90 01 04 66 83 c1 63 89 b4 3b 90 01 04 83 c7 04 8b 1d 90 01 04 66 03 cb 0f b7 d1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}