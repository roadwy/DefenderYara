
rule Trojan_BAT_Remcos_SLYW_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SLYW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 04 00 00 06 72 01 00 00 70 72 33 00 00 70 28 05 00 00 06 72 4d 00 00 70 72 99 00 00 70 28 06 00 00 06 20 00 00 00 00 7e ?? 00 00 04 7b [0-0a] 0f 00 00 00 26 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}