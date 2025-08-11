
rule Trojan_BAT_Taskun_AEQA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AEQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0b 74 02 00 00 1b 11 0c 94 13 0d 11 04 11 0d 19 5a 11 0d 18 63 59 6a 58 13 04 11 04 11 04 1b 62 11 04 19 63 60 61 13 04 11 0c 17 58 13 0c 11 0c 11 0b 74 02 00 00 1b 8e 69 32 c4 } //5
		$a_01_1 = {06 74 02 00 00 1b 11 07 11 07 1f 11 5a 11 07 18 62 61 20 aa 00 00 00 60 9e 11 07 17 58 13 07 11 07 06 75 02 00 00 1b 8e 69 fe 04 13 08 11 08 2d cf } //2
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}