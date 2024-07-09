
rule Trojan_BAT_AsyncRAT_MAAC_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MAAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 06 18 6f 12 00 00 0a 06 6f 13 00 00 0a 02 16 02 8e 69 } //10
		$a_01_1 = {4c 00 6e 00 76 00 62 00 6b 00 65 00 } //1 Lnvbke
		$a_01_2 = {64 00 61 00 6f 00 4c 00 } //1 daoL
		$a_01_3 = {66 00 37 00 78 00 70 00 } //1 f7xp
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}