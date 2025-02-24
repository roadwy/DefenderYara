
rule Trojan_BAT_Rozena_SCXF_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SCXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 06 94 0d 08 09 06 11 06 91 9c 11 06 17 58 13 06 11 06 07 8e 69 32 e7 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}