
rule Trojan_BAT_Remcos_AMMH_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 16 5d 91 [0-20] 17 58 08 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}