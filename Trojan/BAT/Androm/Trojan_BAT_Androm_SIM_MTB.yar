
rule Trojan_BAT_Androm_SIM_MTB{
	meta:
		description = "Trojan:BAT/Androm.SIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 20 03 e5 36 19 28 09 00 00 06 07 6f 12 00 00 06 74 1b 00 00 01 0d 02 09 02 7b 0d 00 00 04 6f 16 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}