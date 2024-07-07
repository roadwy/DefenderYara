
rule Trojan_Win32_LokiBot_RPR_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 4d ec 8b 45 ec 29 45 fc 89 7d f4 8b 45 e0 01 45 f4 2b 75 f4 ff 4d e8 8b 4d fc 89 75 ec } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LokiBot_RPR_MTB_2{
	meta:
		description = "Trojan:Win32/LokiBot.RPR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2a c8 32 c8 b2 61 2a d1 80 f2 b3 2a d0 32 d0 b1 01 2a ca } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}