
rule Trojan_Win32_PonyStealer_T_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.T!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 8b 1d c0 00 00 00 90 02 04 83 fb 00 74 90 01 01 eb 90 00 } //01 00 
		$a_03_1 = {8b 04 0a d9 d0 01 f3 0f 6e c0 90 02 10 0f 6e 0b 90 02 10 0f ef c1 51 0f 7e c1 90 02 10 88 c8 90 02 10 59 29 f3 83 c3 01 75 90 01 01 90 02 10 89 fb 89 04 0a 83 c1 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}