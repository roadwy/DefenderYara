
rule Trojan_BAT_ClipBanker_MX_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 28 0d 00 00 06 0a 06 28 10 00 00 06 0b } //1
		$a_01_1 = {06 28 11 00 00 06 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}