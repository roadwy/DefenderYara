
rule Trojan_BAT_Seraph_ASDV_MTB{
	meta:
		description = "Trojan:BAT/Seraph.ASDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 05 73 ?? 01 00 0a 0b 07 11 04 11 05 6f ?? 01 00 0a 13 06 73 ?? 00 00 0a 0a 03 75 ?? 00 00 1b 73 ?? 01 00 0a 0c 08 11 06 16 73 ?? 01 00 0a 0d 09 06 6f ?? 01 00 0a 73 ?? 01 00 06 06 6f ?? 00 00 0a 28 ?? 01 00 06 de } //1
		$a_01_1 = {11 10 1e 63 d1 13 10 11 1c 11 09 91 13 25 11 1c 11 09 11 23 11 25 61 19 11 19 58 61 11 35 61 d2 9c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}