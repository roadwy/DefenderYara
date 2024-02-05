
rule Trojan_Win32_Redline_GEH_MTB{
	meta:
		description = "Trojan:Win32/Redline.GEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8a 3c 3e 8b c6 83 e0 90 01 01 8a 98 90 01 04 32 df e8 90 01 04 50 e8 90 01 04 2a df 00 1c 3e 46 59 3b f5 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}