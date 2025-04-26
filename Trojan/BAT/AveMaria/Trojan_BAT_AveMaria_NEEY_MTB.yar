
rule Trojan_BAT_AveMaria_NEEY_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 02 03 02 8e 69 5d 91 06 03 06 8e 69 5d 91 61 28 ?? 00 00 0a 02 03 17 d6 02 8e 69 5d 91 28 ?? 00 00 0a da } //10
		$a_01_1 = {51 74 61 2e 42 69 74 6d 61 70 56 69 65 77 2e 72 65 73 6f 75 72 63 65 73 } //2 Qta.BitmapView.resources
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2) >=12
 
}