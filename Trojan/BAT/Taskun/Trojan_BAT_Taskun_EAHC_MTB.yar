
rule Trojan_BAT_Taskun_EAHC_MTB{
	meta:
		description = "Trojan:BAT/Taskun.EAHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 07 0f 00 28 77 00 00 0a 5a 1f 64 5d 9e 07 17 58 0b 07 06 8e 69 32 e7 } //5
		$a_01_1 = {1f 41 08 58 d1 0d 12 03 28 7d 00 00 0a 72 0b 02 00 70 07 08 8f 56 00 00 01 28 7e 00 00 0a 28 7f 00 00 0a 13 04 04 07 08 91 6f 80 00 00 0a 08 17 58 0c 08 03 32 ca } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}