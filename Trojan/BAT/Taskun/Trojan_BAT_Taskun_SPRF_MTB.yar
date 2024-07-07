
rule Trojan_BAT_Taskun_SPRF_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPRF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 07 09 18 6f 90 01 03 0a 20 03 02 00 00 28 90 01 03 0a 13 05 08 11 05 6f 90 01 03 0a 00 09 18 58 0d 00 09 07 6f 90 01 03 0a fe 04 13 06 11 06 2d ce 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}