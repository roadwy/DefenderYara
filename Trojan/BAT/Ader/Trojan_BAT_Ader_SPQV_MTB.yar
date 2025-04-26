
rule Trojan_BAT_Ader_SPQV_MTB{
	meta:
		description = "Trojan:BAT/Ader.SPQV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 16 06 16 95 07 16 95 5a 20 f1 13 22 1d 58 9e 06 17 06 17 95 07 17 95 58 20 a7 a4 be 03 61 9e } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}