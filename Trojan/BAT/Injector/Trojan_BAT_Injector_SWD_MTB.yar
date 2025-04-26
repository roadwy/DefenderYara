
rule Trojan_BAT_Injector_SWD_MTB{
	meta:
		description = "Trojan:BAT/Injector.SWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0d 11 09 28 ?? 00 00 06 26 11 06 28 ?? 00 00 0a 13 0e 11 09 20 88 00 00 00 28 ?? 00 00 0a 13 0f 11 0c 11 0f 1f 10 6a 58 11 0e 1e 16 6a 28 ?? 00 00 06 26 11 09 20 80 00 00 00 11 06 09 6a 58 28 ?? 00 00 0a 00 11 0d 11 09 28 ?? 00 00 06 26 11 0d 28 ?? 00 00 06 26 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}