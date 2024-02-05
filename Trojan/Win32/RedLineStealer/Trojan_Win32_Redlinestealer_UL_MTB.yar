
rule Trojan_Win32_Redlinestealer_UL_MTB{
	meta:
		description = "Trojan:Win32/Redlinestealer.UL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 08 8b 45 90 01 01 ba 90 01 04 f7 75 90 01 01 8b 45 90 01 01 01 d0 0f b6 00 83 f0 90 01 01 89 c3 8b 55 90 01 01 8b 45 90 01 01 01 d0 31 d9 89 ca 88 10 83 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}