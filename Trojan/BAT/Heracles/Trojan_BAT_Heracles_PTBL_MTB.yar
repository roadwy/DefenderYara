
rule Trojan_BAT_Heracles_PTBL_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PTBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 32 09 00 70 28 ?? 00 00 0a 7e 03 00 00 04 72 40 09 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 72 b4 05 00 70 28 ?? 00 00 0a 73 14 00 00 0a 0c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}