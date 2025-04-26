
rule Trojan_BAT_Taskun_PHE_MTB{
	meta:
		description = "Trojan:BAT/Taskun.PHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 06 } //6
		$a_03_1 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0a } //5
		$a_03_2 = {04 06 08 91 6f ?? 00 00 0a 00 00 08 17 58 0c 08 03 fe 04 13 04 11 04 2d ca } //3
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5+(#a_03_2  & 1)*3) >=14
 
}