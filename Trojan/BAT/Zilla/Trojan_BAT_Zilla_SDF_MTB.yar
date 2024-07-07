
rule Trojan_BAT_Zilla_SDF_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 05 16 11 05 8e 69 11 06 16 6f 90 01 03 0a 13 07 09 11 06 11 07 6f 90 01 03 0a 26 de 1a 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}