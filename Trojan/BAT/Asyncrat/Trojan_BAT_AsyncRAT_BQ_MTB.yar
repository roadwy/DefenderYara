
rule Trojan_BAT_AsyncRAT_BQ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {91 11 04 61 09 11 06 91 61 } //4
		$a_03_1 = {07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 08 18 58 0c 08 06 } //2
	condition:
		((#a_01_0  & 1)*4+(#a_03_1  & 1)*2) >=6
 
}