
rule Trojan_BAT_Rozena_KAC_MTB{
	meta:
		description = "Trojan:BAT/Rozena.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 06 5d 94 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 ?? 08 09 11 ?? d2 9c 00 09 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}