
rule Trojan_BAT_PureLogs_SS_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 0c 00 00 06 0a dd 18 00 00 00 26 20 88 13 00 00 28 0f 00 00 0a dd 00 00 00 00 08 17 58 0c 08 07 32 dc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}