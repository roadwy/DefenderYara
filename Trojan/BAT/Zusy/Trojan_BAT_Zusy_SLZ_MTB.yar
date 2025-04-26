
rule Trojan_BAT_Zusy_SLZ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 0b 00 00 0a 72 01 00 00 70 28 0c 00 00 0a 6f ?? ?? ?? 0a 13 04 12 04 28 0e 00 00 0a 2d 43 02 16 7d ?? ?? ?? 04 02 11 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}