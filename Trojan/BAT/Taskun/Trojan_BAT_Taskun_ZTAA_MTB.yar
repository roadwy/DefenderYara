
rule Trojan_BAT_Taskun_ZTAA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZTAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 03 11 0e 18 5a 18 28 ?? 00 00 06 1f 10 28 ?? 00 00 06 d2 8c 40 00 00 01 28 ?? 00 00 06 26 } //3
		$a_03_1 = {11 09 14 72 fc 04 00 70 18 8d 18 00 00 01 25 16 16 8c 03 00 00 01 a2 25 17 11 00 a2 14 14 28 ?? 00 00 06 13 0a } //2
		$a_03_2 = {11 05 d0 40 00 00 01 28 ?? 00 00 06 28 ?? 00 00 06 74 03 00 00 1b 13 06 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1) >=6
 
}