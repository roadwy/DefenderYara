
rule Trojan_BAT_MassLogger_HHF_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.HHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 06 28 ?? 00 00 2b 00 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}