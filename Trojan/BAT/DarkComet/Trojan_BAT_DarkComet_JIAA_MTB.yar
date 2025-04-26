
rule Trojan_BAT_DarkComet_JIAA_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.JIAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 11 06 6f ?? 00 00 0a 8c ?? 00 00 01 13 07 08 11 07 28 ?? 00 00 0a 16 8c ?? 00 00 01 6f ?? 00 00 06 03 28 ?? 00 00 0a 28 ?? 00 00 0a 8c ?? 00 00 01 0d 7e ?? 00 00 04 09 28 ?? 00 00 0a 6f ?? 02 00 06 13 04 } //3
		$a_01_1 = {64 00 61 00 77 00 61 00 64 00 77 00 61 00 64 00 61 00 77 00 64 00 61 00 } //1 dawadwadawda
		$a_01_2 = {23 00 62 00 6e 00 64 00 65 00 72 00 74 00 70 00 23 00 } //1 #bndertp#
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}