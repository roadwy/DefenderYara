
rule Trojan_BAT_DCRat_PSTG_MTB{
	meta:
		description = "Trojan:BAT/DCRat.PSTG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 0c 00 00 0a 13 05 11 04 8d 08 00 00 01 13 06 11 05 11 06 16 11 04 6f 0a 00 00 0a 26 11 06 13 07 dd 1c 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}