
rule Trojan_Win32_Coroxy_MR_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 0c 30 [0-02] 81 fb [0-04] 90 18 47 3b fb 90 18 81 fb [0-04] 90 18 e8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}