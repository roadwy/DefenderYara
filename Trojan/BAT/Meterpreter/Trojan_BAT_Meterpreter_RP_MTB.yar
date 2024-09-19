
rule Trojan_BAT_Meterpreter_RP_MTB{
	meta:
		description = "Trojan:BAT/Meterpreter.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 6f 16 00 00 0a 74 1e 00 00 01 72 ?? 00 00 70 6f 17 00 00 0a a5 1f 00 00 01 76 6b 22 00 00 80 44 5b 22 00 00 80 44 5b 6c 0a 07 6f 18 00 00 0a 2d ce } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}