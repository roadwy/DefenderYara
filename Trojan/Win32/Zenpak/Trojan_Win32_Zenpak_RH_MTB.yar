
rule Trojan_Win32_Zenpak_RH_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 e1 8b 44 24 90 01 01 29 d0 d1 e8 01 d0 c1 e8 04 6b c0 13 8b 4c 24 90 01 01 29 c1 89 c8 83 e8 0a 89 4c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}