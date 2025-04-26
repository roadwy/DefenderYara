
rule Trojan_BAT_Androm_PTAB_MTB{
	meta:
		description = "Trojan:BAT/Androm.PTAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 28 1c 00 00 06 7d 0b 00 00 04 06 7b 0b 00 00 04 2c ed } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}