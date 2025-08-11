
rule Trojan_BAT_AntiVM_SWA_MTB{
	meta:
		description = "Trojan:BAT/AntiVM.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 07 25 4b 11 0e 11 11 1f 0f 5f 95 61 54 11 0e 11 11 1f 0f 5f 11 0e 11 11 1f 0f 5f 95 11 07 25 1a 58 13 07 4b 61 20 19 28 bb 3d 58 9e 11 11 17 58 13 11 00 11 20 17 58 13 20 11 20 11 08 fe 05 13 21 11 21 2d b9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}