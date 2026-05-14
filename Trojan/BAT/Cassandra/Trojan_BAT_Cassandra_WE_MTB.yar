
rule Trojan_BAT_Cassandra_WE_MTB{
	meta:
		description = "Trojan:BAT/Cassandra.WE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 11 04 11 05 6f ?? 00 00 0a 13 06 12 06 28 ?? 00 00 0a 28 ?? 00 00 0a 16 07 08 1a 28 ?? 00 00 0a 08 1a 58 0c 11 05 17 58 13 05 11 05 06 } //5
		$a_03_1 = {02 11 04 09 6f ?? 00 00 0a 13 05 08 11 04 09 11 05 6f ?? 00 00 0a 16 } //2
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=8
 
}