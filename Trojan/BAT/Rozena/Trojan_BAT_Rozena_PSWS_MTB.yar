
rule Trojan_BAT_Rozena_PSWS_MTB{
	meta:
		description = "Trojan:BAT/Rozena.PSWS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 20 c5 00 00 00 28 ?? 00 00 0a 13 05 1c 13 06 11 04 8e 69 8d 1d 00 00 01 13 07 16 13 0b 2b 22 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}