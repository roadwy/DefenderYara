
rule Trojan_BAT_Taskun_APOA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.APOA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 1b 5a 11 07 19 5a 58 20 f4 01 00 00 5d 20 c8 00 00 00 58 13 08 11 07 1f 1e 5d 1f 0a 58 13 09 08 1f 28 5d 1b 58 13 0a 02 08 11 07 6f ?? 00 00 0a 13 0b 04 03 6f ?? 00 00 0a 59 13 0c 11 0b 11 0c 03 28 ?? 00 00 06 11 07 17 58 13 07 11 07 02 6f ?? 00 00 0a 2f 09 03 6f ?? 00 00 0a 04 32 a0 } //3
		$a_03_1 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}