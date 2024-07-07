
rule Trojan_Win32_Coroxy_SK_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b d0 8b 45 d8 31 10 6a 00 e8 9b 7a f3 ff ba 04 00 00 00 2b d0 01 55 e8 6a 00 e8 8a 7a f3 ff ba 04 00 00 00 2b d0 01 55 d8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}