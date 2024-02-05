
rule Trojan_Win32_Carberp_GHG_MTB{
	meta:
		description = "Trojan:Win32/Carberp.GHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 0f be 82 90 01 04 8b 4d fc 83 c1 01 81 f1 89 00 00 00 2b c1 8b 55 fc 88 82 90 01 04 8b 45 fc 83 c0 01 89 45 fc e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}