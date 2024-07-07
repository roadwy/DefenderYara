
rule Trojan_BAT_Remcos_AIGJ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AIGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 4e 00 16 0d 2b 36 00 07 08 09 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 00 17 13 04 00 28 90 01 03 06 d2 06 28 90 01 03 06 00 00 00 09 17 58 90 00 } //2
		$a_01_1 = {43 00 6f 00 6c 00 6c 00 65 00 63 00 74 00 6f 00 72 00 } //1 Collector
		$a_01_2 = {53 61 6e 66 6f 72 64 31 30 31 } //1 Sanford101
		$a_01_3 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}