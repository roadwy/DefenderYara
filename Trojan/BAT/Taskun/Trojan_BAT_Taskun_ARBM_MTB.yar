
rule Trojan_BAT_Taskun_ARBM_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 1a 09 5d 13 1b 11 1a 11 04 5d 13 1c 07 11 1b 91 13 1d 08 11 1c 6f 90 01 03 0a 13 1e 07 11 1a 17 58 09 5d 91 13 1f 11 1d 11 1e 61 11 1f 59 20 00 01 00 00 58 13 20 07 11 1b 11 20 20 00 01 00 00 5d d2 9c 00 11 1a 17 59 13 1a 11 1a 16 fe 04 16 fe 01 13 21 11 21 2d a6 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}