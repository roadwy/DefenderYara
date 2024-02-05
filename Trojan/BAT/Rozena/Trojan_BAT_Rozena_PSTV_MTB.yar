
rule Trojan_BAT_Rozena_PSTV_MTB{
	meta:
		description = "Trojan:BAT/Rozena.PSTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {03 28 0f 00 00 0a 0b 16 0c 2b 17 07 08 9a 0a 02 17 58 10 00 02 17 31 06 06 6f 10 00 00 0a 08 } //00 00 
	condition:
		any of ($a_*)
 
}