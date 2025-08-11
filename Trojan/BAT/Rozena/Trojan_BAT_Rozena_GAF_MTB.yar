
rule Trojan_BAT_Rozena_GAF_MTB{
	meta:
		description = "Trojan:BAT/Rozena.GAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 61 d2 13 0a 11 0a 18 59 20 ff 00 00 00 5f d2 13 0a 07 11 09 11 0a 9c 11 09 17 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}