
rule Trojan_Win32_VirLock_RPN_MTB{
	meta:
		description = "Trojan:Win32/VirLock.RPN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 c2 88 07 46 47 49 83 f9 00 0f 85 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}