
rule Trojan_BAT_AsyncRAT_MWB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 22 00 06 02 02 6f 90 01 03 0a 17 59 07 59 6f 90 01 03 0a 8c 90 01 03 01 28 90 01 03 0a 0a 00 07 17 58 0b 07 02 6f 90 01 03 0a fe 04 0d 09 2d d1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}