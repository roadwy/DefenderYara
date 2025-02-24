
rule Trojan_BAT_Zusy_HNP_MTB{
	meta:
		description = "Trojan:BAT/Zusy.HNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {52 00 6d 00 46 00 73 00 63 00 32 00 56 00 38 00 52 00 6d 00 46 00 73 00 63 00 32 00 56 00 38 00 } //1 RmFsc2V8RmFsc2V8
	condition:
		((#a_01_0  & 1)*1) >=1
 
}