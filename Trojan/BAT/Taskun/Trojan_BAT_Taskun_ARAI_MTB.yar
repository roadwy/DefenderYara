
rule Trojan_BAT_Taskun_ARAI_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 07 8e 69 5d 07 11 04 07 8e 69 5d 91 08 11 04 1f 16 5d 6f 90 01 03 0a 61 28 90 01 03 0a 07 11 04 17 58 07 8e 69 5d 91 28 90 01 03 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 11 04 15 58 13 04 11 04 16 2f b7 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}