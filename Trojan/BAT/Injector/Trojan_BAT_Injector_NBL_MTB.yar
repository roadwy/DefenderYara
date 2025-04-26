
rule Trojan_BAT_Injector_NBL_MTB{
	meta:
		description = "Trojan:BAT/Injector.NBL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 58 20 ff 00 00 00 5f 0c 09 11 07 08 91 58 20 ff 00 00 00 5f 0d 11 07 08 91 13 09 11 07 08 11 07 09 91 9c 11 07 09 11 09 9c 11 06 11 04 11 07 11 07 08 91 11 07 09 91 58 20 ff 00 00 00 5f 91 06 11 04 91 61 9c 11 04 17 58 13 04 11 04 11 0c 31 ad 11 06 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}