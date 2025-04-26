
rule Trojan_BAT_Taskun_SMEA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SMEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 11 04 } //3
		$a_03_1 = {08 11 05 58 1f 64 5d 13 06 08 11 05 5a 1f 64 5d 13 07 08 11 05 61 1f 64 5d 13 08 02 08 11 05 6f ?? 00 00 0a 13 09 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1) >=4
 
}