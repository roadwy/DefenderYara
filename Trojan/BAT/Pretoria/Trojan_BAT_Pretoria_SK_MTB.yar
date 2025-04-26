
rule Trojan_BAT_Pretoria_SK_MTB{
	meta:
		description = "Trojan:BAT/Pretoria.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 7e 02 00 00 04 8e 69 5d 0b 02 06 02 06 91 7e 02 00 00 04 07 91 61 d2 9c 06 17 58 0a 06 02 8e 69 32 dd } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}