
rule Trojan_BAT_Banload_PSWH_MTB{
	meta:
		description = "Trojan:BAT/Banload.PSWH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 72 2b 00 00 70 28 ?? 00 00 0a 0a 06 28 ?? 00 00 0a 2c 07 06 28 ?? 00 00 0a 26 de 03 26 de 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}