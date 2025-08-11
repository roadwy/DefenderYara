
rule Trojan_BAT_PureLogs_SR_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 28 0c 00 00 06 0a dd 0e 00 00 00 26 dd 00 00 00 00 08 17 58 0c 08 07 32 e6 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}