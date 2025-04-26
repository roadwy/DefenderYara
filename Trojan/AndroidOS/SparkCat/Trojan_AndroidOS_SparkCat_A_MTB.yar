
rule Trojan_AndroidOS_SparkCat_A_MTB{
	meta:
		description = "Trojan:AndroidOS/SparkCat.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {62 01 b9 00 6e 20 5e 06 10 00 6e 20 63 06 30 00 6e 20 5c 06 40 00 6e 20 63 06 50 00 12 03 71 30 bb 06 60 03 54 23 b8 00 12 04 12 15 72 55 19 06 53 40 6e 10 53 06 00 00 0e 00 0d 03 6e 10 53 06 00 00 27 03 } //1
		$a_00_1 = {54 80 25 01 6e 30 30 0d 0a 0b 0c 0c 38 0c 14 00 22 0a 35 01 71 00 26 06 00 00 0c 0b 70 20 f5 05 ba 00 22 0b 58 02 70 40 2b 0c 8b c9 6e 20 00 06 ba 00 0e 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}