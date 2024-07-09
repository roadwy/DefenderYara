
rule Trojan_BAT_AgentTesla_GS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {70 02 08 18 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 03 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6a 61 d1 28 ?? ?? ?? 0a 13 04 06 11 04 6f ?? ?? ?? 0a 26 07 03 6f ?? ?? ?? 0a 17 59 fe 01 13 05 11 05 } //10
		$a_81_1 = {58 4f 52 5f 44 65 63 72 79 70 74 } //1 XOR_Decrypt
		$a_81_2 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_81_3 = {47 5a 49 44 45 4b 4b 4b 4b } //1 GZIDEKKKK
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}