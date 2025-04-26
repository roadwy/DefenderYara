
rule Trojan_BAT_Taskun_ZMAA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 18 5d 2c 0a 02 06 07 6f ?? 00 00 0a 2b 08 02 06 07 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d 12 02 28 ?? 00 00 0a 13 04 12 02 28 ?? 00 00 0a 13 05 12 02 28 ?? 00 00 0a 13 06 19 } //3
		$a_03_1 = {03 11 07 11 0a 11 0d 94 91 6f ?? 00 00 0a 00 11 0b 11 0d 58 13 0b 00 11 0d 17 58 13 0d 11 0d 11 0c fe 04 13 0e 11 0e 2d d6 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}