
rule Trojan_BAT_Cerbu_AMBA_MTB{
	meta:
		description = "Trojan:BAT/Cerbu.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 02 91 20 ?? ff ff ff 5f 1f 18 62 0a 20 ?? 00 00 00 16 39 } //1
		$a_01_1 = {04 02 17 58 91 1f 10 62 60 0a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}