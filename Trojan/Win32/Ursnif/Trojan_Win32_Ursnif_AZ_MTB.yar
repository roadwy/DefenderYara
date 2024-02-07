
rule Trojan_Win32_Ursnif_AZ_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c2 2b d6 a3 90 01 04 81 c2 90 01 04 a1 90 01 04 03 ea ba 90 01 04 8b 8c 18 90 01 04 0f b7 90 00 } //02 00 
		$a_02_1 = {0f b7 c7 8b d6 8b 35 90 01 04 81 c1 90 01 04 6b c0 90 01 01 bf 90 01 04 89 0d 90 01 04 89 8c 1e 90 01 04 83 c3 04 2b d0 90 00 } //00 00 
		$a_00_2 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}