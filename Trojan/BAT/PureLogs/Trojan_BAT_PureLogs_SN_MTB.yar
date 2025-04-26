
rule Trojan_BAT_PureLogs_SN_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 72 01 00 00 70 20 00 01 00 00 14 14 14 6f 18 00 00 0a 26 de 03 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}