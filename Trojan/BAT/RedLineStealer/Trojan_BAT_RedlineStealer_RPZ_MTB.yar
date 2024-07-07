
rule Trojan_BAT_RedlineStealer_RPZ_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 1d 00 00 01 02 50 06 8f 1d 00 00 01 25 71 1d 00 00 01 20 af 00 00 00 59 d2 81 1d 00 00 01 02 50 06 8f 1d 00 00 01 25 71 1d 00 00 01 20 e8 00 00 00 58 d2 81 1d 00 00 01 02 50 06 8f 1d 00 00 01 25 71 1d 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}