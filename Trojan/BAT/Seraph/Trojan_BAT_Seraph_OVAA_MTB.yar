
rule Trojan_BAT_Seraph_OVAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.OVAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 16 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 16 13 04 38 1c 00 00 00 09 08 11 04 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 18 58 13 04 11 04 08 6f ?? 00 00 0a 32 da 06 09 6f ?? 00 00 0a 6f ?? 00 00 0a 06 } //4
		$a_01_1 = {47 65 74 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 GetByteArrayAsync
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}