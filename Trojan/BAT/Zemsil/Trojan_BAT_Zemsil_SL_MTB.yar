
rule Trojan_BAT_Zemsil_SL_MTB{
	meta:
		description = "Trojan:BAT/Zemsil.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 13 11 0f 8f 1c 00 00 01 25 47 7e 03 00 00 04 19 11 0f 5f 19 62 1f 1f 5f 63 d2 61 d2 52 17 11 0f 58 13 0f 11 0f 11 13 8e 69 33 d4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}