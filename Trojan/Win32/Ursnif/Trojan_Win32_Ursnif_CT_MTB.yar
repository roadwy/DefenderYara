
rule Trojan_Win32_Ursnif_CT_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.CT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 47 3c 03 c7 0f b7 50 06 0f b7 70 14 6b d2 28 81 f1 0e 15 00 00 0f b7 c9 03 d0 89 4d f4 } //00 00 
	condition:
		any of ($a_*)
 
}