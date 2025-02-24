
rule Trojan_MacOS_ProxyAgent_F_MTB{
	meta:
		description = "Trojan:MacOS/ProxyAgent.F!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 5f 6d 73 67 73 73 5f 63 6f 6d 6d 61 6e 64 } //1 send_msgss_command
		$a_01_1 = {83 7d dc 10 0f 8d 40 00 00 00 48 8b 45 e0 8b 4d dc c1 e1 03 48 63 c9 48 01 c8 48 89 45 f8 48 8b 45 f8 48 8b 00 48 89 45 f0 48 8b 4d f0 48 0f c9 48 63 45 dc 48 89 8c c5 18 fd ff ff 8b 45 dc 83 c0 01 89 45 } //1
		$a_01_2 = {48 8b 85 68 ff ff ff 48 3b 85 70 ff ff ff 0f 83 4a 00 00 00 48 8b 45 80 48 8b 8d 68 ff ff ff 0f b6 04 08 48 8b 8d 78 ff ff ff 48 8b 95 68 ff ff ff 0f b6 0c 11 31 c8 88 c2 48 8b 45 88 48 8b 8d 68 ff ff ff 88 14 08 48 8b 85 68 ff ff ff 48 83 c0 01 48 89 85 68 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}