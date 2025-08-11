
rule Trojan_BAT_Jalapeno_BP_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 58 20 12 d8 36 57 11 0b 20 1f 00 00 00 5f 62 13 0b 0a 11 0b 20 84 14 01 5f 5a 13 0b 11 06 20 a6 63 ad e9 11 0b 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}