
rule Trojan_BAT_Taskun_AACX_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AACX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 29 11 06 06 08 58 07 09 58 6f 90 01 01 00 00 0a 13 0e 12 0e 28 90 01 01 00 00 0a 13 09 11 05 11 04 11 09 9c 11 04 17 58 13 04 09 17 58 0d 09 17 fe 04 13 0a 11 0a 2d cd 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}