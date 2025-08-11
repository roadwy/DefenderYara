
rule Trojan_BAT_MassLogger_PA_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 47 09 11 08 58 1f 11 5a 20 ?? ?? 00 00 5d d2 61 d2 52 09 1f 1f 5a 08 11 08 91 58 20 ?? ?? 00 00 5d 0d 00 11 08 17 58 13 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}