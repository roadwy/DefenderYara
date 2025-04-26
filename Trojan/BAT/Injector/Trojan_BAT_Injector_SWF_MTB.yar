
rule Trojan_BAT_Injector_SWF_MTB{
	meta:
		description = "Trojan:BAT/Injector.SWF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 02 26 16 2b 02 26 16 20 38 02 00 00 8d 01 00 00 01 25 d0 01 00 00 04 28 02 00 00 06 80 02 00 00 04 20 8a 00 00 00 8d 02 00 00 01 25 d0 03 00 00 04 28 02 00 00 06 80 04 00 00 04 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}