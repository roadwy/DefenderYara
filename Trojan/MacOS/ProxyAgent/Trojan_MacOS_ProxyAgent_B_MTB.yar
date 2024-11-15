
rule Trojan_MacOS_ProxyAgent_B_MTB{
	meta:
		description = "Trojan:MacOS/ProxyAgent.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {55 48 89 e5 41 57 41 56 53 48 83 ec 68 48 89 fb 48 8b 05 29 de 55 00 48 8b 00 48 89 45 e0 c7 45 9c ff ff ff ff 48 8d 75 9c 4c 8d 75 8c bf 03 00 00 00 4c 89 f2 e8 16 b4 2b 00 4c 8d 7d a0 4c 89 ff e8 f2 b3 2b 00 48 8d 75 90 4c 89 ff e8 ec b3 2b 00 48 8b 45 90 } //1
		$a_00_1 = {e8 cc b3 2b 00 85 db 75 1b 48 8b 05 b1 dd 55 00 48 8b 00 48 3b 45 e0 75 14 48 83 c4 68 5b 41 5e 41 5f 5d c3 89 df e8 46 00 00 00 eb dc e8 99 b3 2b 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}