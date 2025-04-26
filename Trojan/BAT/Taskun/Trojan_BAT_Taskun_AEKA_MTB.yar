
rule Trojan_BAT_Taskun_AEKA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AEKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 25 16 02 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 02 1e 63 20 ff 00 00 00 5f d2 9c 25 18 02 20 ff 00 00 00 5f d2 9c 0b 16 0d 38 } //3
		$a_03_1 = {01 25 16 0f 00 20 98 00 00 00 20 fe 00 00 00 28 ?? 00 00 06 9c 25 17 0f 00 20 b7 03 00 00 20 d0 03 00 00 28 ?? 00 00 06 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0b } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}