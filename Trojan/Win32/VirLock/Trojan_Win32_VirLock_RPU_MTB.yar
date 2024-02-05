
rule Trojan_Win32_VirLock_RPU_MTB{
	meta:
		description = "Trojan:Win32/VirLock.RPU!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba 93 00 00 00 8a 06 90 32 c2 90 88 07 90 e9 cf ff ff ff bf 00 40 4b 00 8b df 90 b9 9c 03 00 00 e9 db ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}