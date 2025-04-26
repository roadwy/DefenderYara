
rule Trojan_BAT_Taskun_EAFY_MTB{
	meta:
		description = "Trojan:BAT/Taskun.EAFY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 06 11 07 11 07 1f 11 5a 11 07 18 62 61 20 aa 00 00 00 60 9e 00 11 07 17 58 13 07 11 07 06 8e 69 fe 04 13 08 11 08 2d d7 } //5
		$a_01_1 = {11 0b 11 0c 94 13 0d 00 11 04 11 0d 19 5a 11 0d 18 63 59 6a 58 13 04 11 04 11 04 1b 62 11 04 19 63 60 61 13 04 00 11 0c 17 58 13 0c 11 0c 11 0b 8e 69 32 cc } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}