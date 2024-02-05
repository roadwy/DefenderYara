
rule Trojan_Win32_Copak_GJM_MTB{
	meta:
		description = "Trojan:Win32/Copak.GJM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {83 ec 04 c7 04 24 90 01 04 c3 09 c9 bb 90 01 04 e8 90 01 04 31 1a 42 81 ef 90 01 04 81 e9 90 01 04 39 f2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}