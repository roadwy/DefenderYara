
rule Trojan_BAT_RedLine_PTFG_MTB{
	meta:
		description = "Trojan:BAT/RedLine.PTFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f db 01 00 0a 13 05 28 90 01 01 02 00 06 13 06 11 06 11 05 17 73 dc 01 00 0a 25 06 16 06 8e 69 6f dd 01 00 0a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}