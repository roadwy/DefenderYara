
rule Trojan_BAT_Zemsil_ARA_MTB{
	meta:
		description = "Trojan:BAT/Zemsil.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 06 07 91 7e 05 00 00 04 07 7e 05 00 00 04 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 06 8e 69 32 df } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}