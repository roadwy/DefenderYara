
rule Trojan_BAT_SpyAgent_NIT_MTB{
	meta:
		description = "Trojan:BAT/SpyAgent.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {13 06 02 1f 0a 28 ?? 00 00 06 13 07 28 ?? 00 00 06 72 c0 04 00 70 11 07 6f ?? 00 00 0a 13 08 11 04 11 07 11 06 74 64 00 00 01 28 ?? 00 00 0a 6f ?? 00 00 0a 11 08 72 de 04 00 70 02 1d 28 ?? 00 00 06 11 06 74 64 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 13 08 09 11 08 28 ?? 00 00 0a 0d 11 05 6f ?? 00 00 0a 2d 8d } //2
		$a_01_1 = {46 61 6c 63 6f 6e 5f 4b 65 79 6c 6f 67 67 65 72 } //1 Falcon_Keylogger
		$a_00_2 = {53 00 65 00 6e 00 64 00 20 00 6c 00 6f 00 67 00 73 00 20 00 69 00 6e 00 74 00 65 00 72 00 76 00 61 00 6c 00 } //1 Send logs interval
		$a_01_3 = {63 68 6b 55 41 43 45 78 70 6c 6f 69 74 } //1 chkUACExploit
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}