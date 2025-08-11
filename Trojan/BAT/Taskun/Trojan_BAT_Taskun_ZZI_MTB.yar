
rule Trojan_BAT_Taskun_ZZI_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZZI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 07 } //6
		$a_03_1 = {03 06 08 6f ?? 00 00 0a 0d 0e 04 0e 04 4a 17 58 54 } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}