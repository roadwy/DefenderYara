
rule Trojan_Win32_VirLock_RPO_MTB{
	meta:
		description = "Trojan:Win32/VirLock.RPO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 90 88 07 90 46 47 49 90 83 f9 00 } //1
		$a_01_1 = {8a 06 90 32 c2 88 07 90 46 47 49 90 83 f9 00 } //1
		$a_01_2 = {8a 06 32 c2 88 07 90 46 90 47 90 49 83 f9 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}