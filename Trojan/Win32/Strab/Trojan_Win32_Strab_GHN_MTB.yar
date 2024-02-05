
rule Trojan_Win32_Strab_GHN_MTB{
	meta:
		description = "Trojan:Win32/Strab.GHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {1b c0 83 c0 01 8b 0d 90 01 04 f7 d1 0f af c1 0f bf 55 98 33 95 90 01 04 f7 da 1b d2 83 c2 01 2b c2 a2 90 01 04 a1 90 01 04 33 c9 05 90 01 04 81 d1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}