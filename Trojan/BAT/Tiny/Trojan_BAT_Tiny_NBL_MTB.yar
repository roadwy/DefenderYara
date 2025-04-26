
rule Trojan_BAT_Tiny_NBL_MTB{
	meta:
		description = "Trojan:BAT/Tiny.NBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 05 91 9c 07 11 05 09 9c 07 11 04 91 07 11 05 91 58 20 00 01 00 00 5d 13 07 02 11 06 8f 10 00 00 01 25 71 10 00 00 01 07 11 07 91 61 d2 81 10 00 00 01 11 06 17 58 13 06 11 06 02 16 6f 13 00 00 0a 32 98 02 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}