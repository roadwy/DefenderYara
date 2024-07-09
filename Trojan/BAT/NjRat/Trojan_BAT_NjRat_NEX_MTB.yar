
rule Trojan_BAT_NjRat_NEX_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_03_0 = {fe 01 13 04 11 04 2d dc 28 ?? 00 00 0a 07 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 72 ?? 01 00 70 } //5
		$a_01_1 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //3 Invoke
		$a_01_2 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1) >=9
 
}