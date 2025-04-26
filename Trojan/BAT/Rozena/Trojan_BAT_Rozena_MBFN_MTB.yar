
rule Trojan_BAT_Rozena_MBFN_MTB{
	meta:
		description = "Trojan:BAT/Rozena.MBFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 08 9a 16 18 6f ?? 00 00 0a 25 20 03 02 00 00 28 ?? 00 00 0a 1f 10 5d 0d 20 03 02 00 00 28 ?? 00 00 0a 1f 10 5b 13 04 09 1f 10 5a 11 04 58 13 05 06 08 } //1
		$a_01_1 = {30 00 78 00 38 00 45 00 2c 00 30 00 78 00 38 00 38 00 2c 00 30 00 78 00 35 00 37 00 2c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}