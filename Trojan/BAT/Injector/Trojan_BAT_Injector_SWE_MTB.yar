
rule Trojan_BAT_Injector_SWE_MTB{
	meta:
		description = "Trojan:BAT/Injector.SWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 0a 06 17 58 0a 06 1f 0f 31 f7 28 ?? 00 00 0a 72 b7 00 00 70 28 ?? 00 00 06 74 01 00 00 1b 28 ?? 00 00 06 6f ?? 00 00 0a 28 ?? 00 00 06 20 e8 03 00 00 28 ?? 00 00 0a 2b f4 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}