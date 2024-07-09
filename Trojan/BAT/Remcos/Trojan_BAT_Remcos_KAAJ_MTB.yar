
rule Trojan_BAT_Remcos_KAAJ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.KAAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 61 07 11 ?? 17 58 ?? ?? ?? ?? ?? 5d 91 08 58 08 5d 59 d2 9c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}