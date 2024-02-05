
rule Trojan_Win32_VirLock_RPQ_MTB{
	meta:
		description = "Trojan:Win32/VirLock.RPQ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 06 90 32 c2 90 88 07 90 46 90 47 90 49 90 83 f9 00 90 e9 d2 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}