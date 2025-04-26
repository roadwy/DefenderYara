
rule Trojan_BAT_DarkKomet_SIL_MTB{
	meta:
		description = "Trojan:BAT/DarkKomet.SIL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 6f 66 00 00 0a 03 16 03 8e b7 6f 67 00 00 0a 0a de 17 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}