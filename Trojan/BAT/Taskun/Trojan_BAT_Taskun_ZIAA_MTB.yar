
rule Trojan_BAT_Taskun_ZIAA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZIAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 28 ?? 00 00 06 0c 11 0d } //2
		$a_03_1 = {01 25 16 12 02 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c 13 06 19 8d ?? 00 00 01 25 17 17 9e 25 18 18 9e 13 07 11 0d } //3
		$a_03_2 = {03 11 06 11 07 11 08 94 91 6f ?? 00 00 0a 00 20 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*3+(#a_03_2  & 1)*2) >=7
 
}