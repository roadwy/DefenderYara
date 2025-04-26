
rule Trojan_BAT_Bobik_PTFJ_MTB{
	meta:
		description = "Trojan:BAT/Bobik.PTFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 06 16 07 6f 8b 01 00 0a 02 06 16 06 8e 69 6f 8c 01 00 0a 25 0b 16 30 e7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}