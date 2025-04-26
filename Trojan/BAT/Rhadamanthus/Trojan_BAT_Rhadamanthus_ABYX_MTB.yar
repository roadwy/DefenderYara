
rule Trojan_BAT_Rhadamanthus_ABYX_MTB{
	meta:
		description = "Trojan:BAT/Rhadamanthus.ABYX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 0d 00 00 70 28 ?? 00 00 06 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 0b dd ?? 00 00 00 26 de d6 07 2a } //2
		$a_01_1 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 ReadAsByteArrayAsync
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}