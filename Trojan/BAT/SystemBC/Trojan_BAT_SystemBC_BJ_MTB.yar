
rule Trojan_BAT_SystemBC_BJ_MTB{
	meta:
		description = "Trojan:BAT/SystemBC.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 09 07 08 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 13 05 11 05 11 04 17 73 ?? 00 00 0a 13 06 2b 0c 00 28 ?? 00 00 06 0a de 03 26 de 00 06 2c f1 11 06 06 16 06 8e 69 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 0a de 18 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}