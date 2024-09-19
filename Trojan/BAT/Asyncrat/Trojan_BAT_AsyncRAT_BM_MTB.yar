
rule Trojan_BAT_AsyncRAT_BM_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 09 08 11 09 91 11 04 61 09 11 06 91 61 28 } //4
		$a_03_1 = {08 8e 69 17 59 91 1f ?? 61 13 04 } //2
	condition:
		((#a_01_0  & 1)*4+(#a_03_1  & 1)*2) >=6
 
}