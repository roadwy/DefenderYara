
rule Trojan_Win32_VirLock_RPR_MTB{
	meta:
		description = "Trojan:Win32/VirLock.RPR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 88 07 46 47 49 83 f9 00 } //00 00 
	condition:
		any of ($a_*)
 
}