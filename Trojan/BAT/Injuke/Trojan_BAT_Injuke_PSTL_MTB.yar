
rule Trojan_BAT_Injuke_PSTL_MTB{
	meta:
		description = "Trojan:BAT/Injuke.PSTL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 72 73 00 00 70 28 90 01 01 00 00 06 00 07 72 df 00 00 70 28 90 01 01 00 00 0a 0c 07 0d 73 18 00 00 0a 13 06 00 11 06 72 f1 00 00 70 08 6f 90 01 01 00 00 0a 00 00 de 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}