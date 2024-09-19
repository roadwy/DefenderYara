
rule Trojan_BAT_Jalapeno_SCAA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.SCAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {02 06 02 06 91 66 d2 9c 08 } //1
		$a_03_1 = {02 06 8f 24 00 00 01 25 71 ?? 00 00 01 20 ?? 00 00 00 59 d2 81 ?? 00 00 01 08 } //2
		$a_03_2 = {02 06 8f 24 00 00 01 25 71 ?? 00 00 01 1f ?? 58 d2 81 ?? 00 00 01 08 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=5
 
}