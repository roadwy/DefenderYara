
rule Trojan_Win64_XmrigMiner_RP_MTB{
	meta:
		description = "Trojan:Win64/XmrigMiner.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f } //1 stratum+tcp://
		$a_01_1 = {73 74 72 61 74 75 6d 2b 73 73 6c 3a 2f 2f } //1 stratum+ssl://
		$a_01_2 = {64 6f 6e 61 74 65 2e 76 32 2e 78 6d 72 69 67 2e 63 6f 6d } //1 donate.v2.xmrig.com
		$a_01_3 = {48 57 4c 4f 43 5f 43 50 55 49 44 5f 50 41 54 48 } //1 HWLOC_CPUID_PATH
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}