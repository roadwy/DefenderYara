
rule Trojan_BAT_Formbook_SS_MTB{
	meta:
		description = "Trojan:BAT/Formbook.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 6a 53 00 70 0a 06 28 51 00 00 06 72 ef 53 00 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 2b 0b 73 1c 01 00 06 07 28 3f 01 00 06 28 28 00 00 0a 0c 73 9d 01 00 06 0d 09 73 83 01 00 06 28 ?? ?? ?? 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}