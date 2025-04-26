
rule Trojan_BAT_Rozena_KAD_MTB{
	meta:
		description = "Trojan:BAT/Rozena.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 06 07 08 03 58 09 59 1f 1a 5d 09 58 d1 9d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}