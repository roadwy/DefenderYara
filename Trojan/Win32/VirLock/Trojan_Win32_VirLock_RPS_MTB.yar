
rule Trojan_Win32_VirLock_RPS_MTB{
	meta:
		description = "Trojan:Win32/VirLock.RPS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 c2 90 88 07 90 46 90 47 90 49 90 83 f9 00 90 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}