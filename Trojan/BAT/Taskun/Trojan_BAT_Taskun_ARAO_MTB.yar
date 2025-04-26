
rule Trojan_BAT_Taskun_ARAO_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 0d 06 17 58 13 0a 06 20 00 9a 01 00 5d 13 04 11 0a 20 00 9a 01 00 5d 13 0b 07 11 04 91 13 0c 1f 16 8d ?? ?? ?? 01 25 d0 ?? 00 00 04 28 ?? ?? ?? 0a 06 1f 16 5d 91 13 0d 07 11 0b 91 09 58 13 0e 11 0c 11 0d 61 13 0f 11 0f 11 0e 59 13 10 07 11 04 11 10 09 5d d2 9c 06 17 58 0a 06 11 06 fe 04 13 11 11 11 2d 95 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}