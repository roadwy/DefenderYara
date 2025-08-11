
rule Trojan_BAT_PureLogs_SY_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.SY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 2d 00 00 0a 25 6f 2e 00 00 0a 72 51 01 00 70 72 67 01 00 70 6f 2f 00 00 0a 25 72 5e 02 00 70 6f 30 00 00 0a 0a 6f 31 00 00 0a dd 09 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}