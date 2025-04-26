
rule Trojan_BAT_Taskun_ATIA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ATIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 0f 01 1f 25 1f 38 28 ?? 00 00 06 9c 25 17 0f 01 20 98 03 00 00 20 86 03 00 00 28 ?? 00 00 06 9c 25 18 0f 01 20 f3 02 00 00 20 ec 02 00 00 28 ?? 00 00 06 9c 6f ?? 00 00 0a 19 0d } //4
		$a_03_1 = {01 25 16 0f 00 20 73 01 00 00 20 6e 01 00 00 28 ?? 00 00 06 9c 25 17 0f 00 1f 09 1f 17 28 ?? 00 00 06 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0a 18 0c 2b a1 } //2
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2) >=6
 
}