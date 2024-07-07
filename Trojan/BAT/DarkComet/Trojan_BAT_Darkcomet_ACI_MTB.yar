
rule Trojan_BAT_Darkcomet_ACI_MTB{
	meta:
		description = "Trojan:BAT/Darkcomet.ACI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 07 8e 69 5d 91 08 06 58 07 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 81 0c 00 00 01 08 17 58 0c 08 02 8e 69 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}