
rule Trojan_BAT_Seraph_AAVQ_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAVQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 00 11 02 02 11 02 91 72 ?? 00 00 70 28 ?? 00 00 06 59 d2 9c } //4
		$a_01_1 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 ReadAsByteArrayAsync
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}