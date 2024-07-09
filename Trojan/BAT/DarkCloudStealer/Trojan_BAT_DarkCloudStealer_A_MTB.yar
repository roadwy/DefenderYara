
rule Trojan_BAT_DarkCloudStealer_A_MTB{
	meta:
		description = "Trojan:BAT/DarkCloudStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 00 01 25 16 1f ?? 9d 6f ?? ?? 00 0a 0b 90 09 05 00 00 0a 17 8d } //2
		$a_03_1 = {00 00 01 25 16 1f ?? 9d 6f ?? ?? 00 0a 0d 90 09 05 00 00 04 17 8d } //2
		$a_03_2 = {08 06 07 06 9a 1f 10 28 ?? ?? 00 0a 9c 06 17 d6 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=6
 
}