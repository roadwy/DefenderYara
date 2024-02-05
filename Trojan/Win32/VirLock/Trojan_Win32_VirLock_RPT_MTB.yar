
rule Trojan_Win32_VirLock_RPT_MTB{
	meta:
		description = "Trojan:Win32/VirLock.RPT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 90 88 07 46 47 49 90 83 f9 00 90 e9 12 00 00 00 8b df 90 b9 80 03 00 00 ba d5 00 00 00 e9 da ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_VirLock_RPT_MTB_2{
	meta:
		description = "Trojan:Win32/VirLock.RPT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 47 49 83 f9 00 0f 85 1a 00 00 00 e9 20 00 00 00 81 ec e0 02 00 00 be b8 d0 4a 00 e9 ce ff ff ff ba 02 00 00 00 8a 06 32 c2 88 07 e9 cf ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}