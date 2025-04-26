
rule Trojan_BAT_Crysan_PLLZH_MTB{
	meta:
		description = "Trojan:BAT/Crysan.PLLZH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 00 00 fe 0d 03 00 28 ?? 00 00 0a 6f ?? 00 00 0a fe 0c 00 00 fe 0d 03 00 28 ?? 00 00 0a 6f ?? 00 00 0a fe 0c 00 00 fe 0d 03 00 28 ?? 00 00 0a 6f ?? 00 00 0a fe 0c 02 00 } //6
		$a_03_1 = {fe 09 00 00 fe 0c 01 00 fe 0c 02 00 6f ?? 00 00 0a fe 0e 03 00 } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}