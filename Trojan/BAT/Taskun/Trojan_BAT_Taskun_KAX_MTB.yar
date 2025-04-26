
rule Trojan_BAT_Taskun_KAX_MTB{
	meta:
		description = "Trojan:BAT/Taskun.KAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 06 02 19 8d ?? 00 00 01 25 16 11 06 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 06 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 06 20 ff 00 00 00 5f d2 9c } //3
		$a_03_1 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0a } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}