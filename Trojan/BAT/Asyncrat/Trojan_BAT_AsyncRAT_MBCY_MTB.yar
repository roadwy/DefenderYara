
rule Trojan_BAT_AsyncRAT_MBCY_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBCY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 13 05 2b b9 16 0a 1e 13 05 2b b2 03 04 61 1f 17 59 06 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}