
rule Trojan_BAT_Injuke_RI_MTB{
	meta:
		description = "Trojan:BAT/Injuke.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 11 08 11 0a 11 0d d3 18 5a 58 49 d3 1a 5a 58 } //5
		$a_01_1 = {24 00 50 00 41 00 53 00 53 00 57 00 4f 00 52 00 44 00 24 00 } //1 $PASSWORD$
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}