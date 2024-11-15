
rule Trojan_BAT_Formbook_RDAY_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 06 07 28 0c 00 00 06 0c 04 03 6f 1d 00 00 0a 59 0d 03 08 09 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}