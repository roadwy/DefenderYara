
rule Trojan_BAT_Zemsil_SI_MTB{
	meta:
		description = "Trojan:BAT/Zemsil.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 17 58 0b 07 06 8e 69 fe 04 13 06 11 06 2d ce } //2
		$a_01_1 = {42 6f 6d 62 6f 73 46 6f 72 6d 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 BombosForm.Form1.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}