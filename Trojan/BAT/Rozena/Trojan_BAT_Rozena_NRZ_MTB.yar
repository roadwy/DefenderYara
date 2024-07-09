
rule Trojan_BAT_Rozena_NRZ_MTB{
	meta:
		description = "Trojan:BAT/Rozena.NRZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 06 07 11 06 91 18 59 20 ?? 00 00 00 5f d2 9c 11 06 17 58 13 06 11 06 07 8e 69 } //5
		$a_03_1 = {28 01 00 00 06 0d 07 16 09 08 28 ?? 00 00 0a 7e ?? 00 00 0a 16 09 7e ?? 00 00 0a 16 7e ?? 00 00 0a 28 ?? 00 00 06 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}