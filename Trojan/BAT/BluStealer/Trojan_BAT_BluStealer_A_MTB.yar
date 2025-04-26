
rule Trojan_BAT_BluStealer_A_MTB{
	meta:
		description = "Trojan:BAT/BluStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 00 01 25 16 1f 2d 9d 6f 90 09 06 00 00 00 0a 17 8d } //2
		$a_03_1 = {07 06 11 08 9a 1f 10 28 ?? 00 00 0a 8c ?? 00 00 01 6f ?? 00 00 0a 26 11 08 17 58 13 08 11 08 06 8e 69 } //2
		$a_03_2 = {00 00 01 25 16 1f 25 9d 6f 22 00 00 0a 90 09 06 00 00 00 04 17 8d } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=6
 
}