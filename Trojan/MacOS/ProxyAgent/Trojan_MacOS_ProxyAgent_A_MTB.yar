
rule Trojan_MacOS_ProxyAgent_A_MTB{
	meta:
		description = "Trojan:MacOS/ProxyAgent.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 4c 8b 34 25 30 00 00 00 48 8b 05 87 da 5c 00 48 8b 0c 24 48 89 ca 48 29 c1 0f 1f 44 00 00 48 85 c9 7f 0f b8 01 00 00 00 48 8b 6c 24 08 48 83 c4 10 } //1
		$a_01_1 = {0f 57 d2 f2 48 0f 2a d3 f2 0f 58 d0 f2 0f 5c c8 0f 57 c0 f2 48 0f 2a c1 f2 0f 59 c1 f2 0f 10 0d e4 f1 39 00 f2 0f 59 c8 f2 0f 58 d1 f2 0f 10 05 c4 f2 39 00 f2 0f 5c d0 0f 57 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}