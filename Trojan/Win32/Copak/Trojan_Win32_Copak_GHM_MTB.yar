
rule Trojan_Win32_Copak_GHM_MTB{
	meta:
		description = "Trojan:Win32/Copak.GHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 14 24 8b 14 24 83 c4 04 e8 90 01 04 01 f2 81 c2 90 01 04 31 19 81 c1 90 01 04 39 c1 75 90 01 01 81 ea 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}