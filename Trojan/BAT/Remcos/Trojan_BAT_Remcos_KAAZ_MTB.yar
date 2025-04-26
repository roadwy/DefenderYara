
rule Trojan_BAT_Remcos_KAAZ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.KAAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {95 d7 20 ff 00 00 00 5f [0-32] 95 d7 20 ff 00 00 00 5f 95 61 86 9c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}