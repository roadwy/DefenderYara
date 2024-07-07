
rule Trojan_Win32_ProxyAgent_GKM_MTB{
	meta:
		description = "Trojan:Win32/ProxyAgent.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 e9 03 89 0d 90 01 04 8b 15 90 01 04 2b 15 90 01 04 89 15 90 01 04 a1 90 01 04 03 05 90 01 04 a3 90 01 04 b9 87 8a 00 00 85 c9 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}