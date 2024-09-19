
rule Trojan_BAT_Remcos_SPDG_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SPDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 d1 13 14 11 1d 11 09 91 13 22 11 1d 11 09 11 21 11 22 61 11 1f 19 58 61 11 34 61 d2 9c } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}