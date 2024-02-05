
rule Trojan_Win32_Relinestealer_UH_MTB{
	meta:
		description = "Trojan:Win32/Relinestealer.UH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 d8 31 d2 f7 75 90 01 01 8b 45 90 01 01 0f be 04 10 69 c0 90 01 04 30 04 1e 43 90 00 } //0a 00 
		$a_03_1 = {0f be d9 77 90 01 01 83 c9 90 01 01 0f be d9 31 fb 69 fb 90 01 04 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}