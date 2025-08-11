
rule Trojan_BAT_Rozena_ECM_MTB{
	meta:
		description = "Trojan:BAT/Rozena.ECM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 09 06 09 91 18 59 20 ff 00 00 00 5f d2 9c 09 17 58 0d 09 06 8e 69 32 e7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}