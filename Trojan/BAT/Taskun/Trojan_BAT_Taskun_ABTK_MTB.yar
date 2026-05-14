
rule Trojan_BAT_Taskun_ABTK_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ABTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 11 11 12 6f ?? 00 00 0a 13 13 11 0b 03 fe 04 13 14 11 14 2c 17 00 11 08 12 13 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0b 17 58 13 0b } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_BAT_Taskun_ABTK_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.ABTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 14 11 16 18 6f ?? ?? ?? 0a 20 03 02 00 00 28 ?? ?? ?? 0a 13 18 11 15 11 18 6f ?? ?? ?? 0a 00 11 16 18 58 13 16 00 11 16 11 14 6f ?? ?? ?? 0a fe 04 13 19 11 19 2d c7 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}