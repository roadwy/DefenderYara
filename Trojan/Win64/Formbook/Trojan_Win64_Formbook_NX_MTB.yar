
rule Trojan_Win64_Formbook_NX_MTB{
	meta:
		description = "Trojan:Win64/Formbook.NX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 0f b6 bb f8 04 00 00 33 db 40 80 f6 97 41 80 f4 35 41 80 f5 d4 41 80 f6 53 41 80 f7 1e 40 80 f7 2c } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}