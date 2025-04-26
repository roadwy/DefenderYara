
rule Trojan_BAT_Taskun_ZHV_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZHV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 05 0f 00 28 ?? 00 00 0a 13 06 0f 00 28 ?? 00 00 0a 13 07 04 19 8d ?? 00 00 01 25 16 11 05 9c 25 17 11 06 9c 25 18 11 07 9c 6f ?? 00 00 0a 00 } //6
		$a_03_1 = {0a 58 02 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}