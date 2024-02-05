
rule Trojan_Win32_VirLock_RPP_MTB{
	meta:
		description = "Trojan:Win32/VirLock.RPP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 06 90 e9 00 00 00 00 32 c2 90 88 07 90 46 90 47 90 49 90 83 f9 00 90 0f 85 e2 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_VirLock_RPP_MTB_2{
	meta:
		description = "Trojan:Win32/VirLock.RPP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 88 07 46 90 47 90 49 } //01 00 
		$a_01_1 = {8a 06 32 c2 88 07 46 47 e9 00 00 00 00 49 83 f9 00 } //00 00 
	condition:
		any of ($a_*)
 
}