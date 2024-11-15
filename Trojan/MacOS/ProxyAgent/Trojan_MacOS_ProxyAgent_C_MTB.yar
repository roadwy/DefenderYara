
rule Trojan_MacOS_ProxyAgent_C_MTB{
	meta:
		description = "Trojan:MacOS/ProxyAgent.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 41 57 41 56 41 54 53 48 89 fb e8 4d 27 06 00 49 89 c6 e8 85 b2 2b 00 c7 00 00 00 00 00 48 8b 3b 48 8b 73 08 48 8b 53 10 48 8b 4b 18 e8 71 b2 2b 00 41 89 c7 e8 63 b2 2b 00 44 8b 20 e8 1b 27 06 00 4c 29 f0 44 89 7c 03 20 44 89 e0 } //1
		$a_03_1 = {4c 89 ff 31 f6 4c 89 ea 4c 89 f1 e8 1d b0 2b 00 89 c3 83 f8 23 75 29 48 c7 45 c0 00 00 00 00 4c 89 65 c8 48 8d 7d c0 31 f6 e8 05 b0 2b 00 49 81 c4 40 42 0f 00 49 81 fc 40 6f 40 01 ?? ?? eb ?? 85 db } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}