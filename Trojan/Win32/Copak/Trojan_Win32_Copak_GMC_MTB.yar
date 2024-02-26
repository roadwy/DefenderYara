
rule Trojan_Win32_Copak_GMC_MTB{
	meta:
		description = "Trojan:Win32/Copak.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {31 31 4a ba f3 5b 16 11 41 21 d2 81 c0 90 01 04 39 d9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Copak_GMC_MTB_2{
	meta:
		description = "Trojan:Win32/Copak.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {83 ec 04 c7 04 24 90 01 04 5f 48 29 d0 09 c2 e8 90 01 04 21 d2 29 d0 21 c2 31 3e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}