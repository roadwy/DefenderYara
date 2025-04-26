
rule Trojan_BAT_Avemaria_AMAB_MTB{
	meta:
		description = "Trojan:BAT/Avemaria.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 03 11 07 11 03 91 11 00 11 03 11 00 28 ?? ?? ?? 06 5d 28 ?? ?? ?? 06 61 d2 9c 20 ?? ?? ?? ?? 38 ?? ?? ?? ?? 11 03 11 07 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}