
rule Trojan_BAT_SystemBC_psyZ_MTB{
	meta:
		description = "Trojan:BAT/SystemBC.psyZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 fe 06 15 00 00 0a 29 0f 00 00 11 72 01 00 00 70 fe 06 16 00 00 0a 29 10 00 00 11 2c 04 17 0b de 04 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}