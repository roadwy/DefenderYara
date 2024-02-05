
rule Trojan_Win32_Copak_VZ_MTB{
	meta:
		description = "Trojan:Win32/Copak.VZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 38 f7 d2 f7 d2 81 e7 90 01 04 4a 09 d3 89 ca 31 3e 42 21 da f7 d2 81 c6 90 01 04 29 ca 81 eb 90 01 04 21 d9 40 f7 d3 09 c9 81 c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}