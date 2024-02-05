
rule Trojan_Win32_Copak_GI_MTB{
	meta:
		description = "Trojan:Win32/Copak.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {31 10 49 81 c0 04 00 00 00 81 ee 90 01 04 39 d8 75 e8 81 c7 90 01 04 c3 89 f6 bf 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Copak_GI_MTB_2{
	meta:
		description = "Trojan:Win32/Copak.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {09 c9 09 d1 39 f0 75 eb c3 ff 74 01 90 01 01 31 17 81 c7 90 01 04 01 c0 4e 39 df 75 ec 09 f1 21 f1 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}