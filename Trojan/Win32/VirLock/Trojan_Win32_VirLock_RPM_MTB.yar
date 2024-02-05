
rule Trojan_Win32_VirLock_RPM_MTB{
	meta:
		description = "Trojan:Win32/VirLock.RPM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 07 90 46 90 47 90 49 90 83 f9 00 90 0f 85 } //00 00 
	condition:
		any of ($a_*)
 
}