
rule Trojan_BAT_Taskun_ARBH_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 08 09 5d 13 09 11 08 11 04 5d 13 0a 07 11 09 91 13 0b 08 11 0a 6f ?? ?? ?? 0a 13 0c 07 11 08 17 58 09 5d 91 13 0d 11 0b 11 0c 61 11 0d 59 20 00 01 00 00 58 13 0e 07 11 09 11 0e 20 00 01 00 00 5d d2 9c 11 08 17 59 13 08 11 08 16 2f b1 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}