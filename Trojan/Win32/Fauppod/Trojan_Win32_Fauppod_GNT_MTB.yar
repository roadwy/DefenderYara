
rule Trojan_Win32_Fauppod_GNT_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 55 14 68 90 01 04 83 c4 04 80 3a 00 90 01 04 ac 32 02 47 88 47 ff 68 90 01 04 83 c4 04 83 ec 04 c7 04 24 90 01 04 83 c4 04 42 83 e9 01 85 c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fauppod_GNT_MTB_2{
	meta:
		description = "Trojan:Win32/Fauppod.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {83 ec 04 c7 04 24 90 01 04 83 c4 04 83 c6 01 8a 46 ff 90 01 01 32 02 90 01 01 47 88 47 ff 90 00 } //0a 00 
		$a_03_1 = {83 c4 04 42 89 c0 89 c0 83 e9 01 83 ec 04 c7 04 24 90 01 04 83 c4 04 85 c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}