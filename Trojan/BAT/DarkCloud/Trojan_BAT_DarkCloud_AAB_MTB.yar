
rule Trojan_BAT_DarkCloud_AAB_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.AAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 14 14 17 8d ?? 00 00 01 25 16 07 6f ?? 00 00 0a a2 28 } //4
		$a_03_1 = {0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0a 16 0b 2b 0d } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}