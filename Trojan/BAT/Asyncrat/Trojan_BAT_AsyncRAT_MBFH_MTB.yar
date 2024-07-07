
rule Trojan_BAT_AsyncRAT_MBFH_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {26 1c 13 05 2b c2 16 0a 1d 13 05 2b bb 04 03 61 1f 31 59 06 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}