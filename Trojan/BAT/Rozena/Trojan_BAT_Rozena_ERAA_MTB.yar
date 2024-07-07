
rule Trojan_BAT_Rozena_ERAA_MTB{
	meta:
		description = "Trojan:BAT/Rozena.ERAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 13 11 17 11 13 11 17 91 18 61 20 ff 00 00 00 5f d2 9c 11 17 17 58 13 17 11 17 11 13 8e 69 32 df } //5
		$a_01_1 = {16 0c 2b 0d 07 08 06 08 91 03 61 d2 9c 08 17 58 0c 08 06 8e 69 32 ed } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}