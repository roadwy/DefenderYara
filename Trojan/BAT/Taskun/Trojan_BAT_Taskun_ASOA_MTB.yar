
rule Trojan_BAT_Taskun_ASOA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ASOA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 09 02 09 11 07 6f ?? 00 00 0a 13 0a 04 03 6f ?? 00 00 0a 59 13 0b 11 0a 11 0b 03 28 ?? 00 00 06 00 00 11 07 17 58 13 07 11 07 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 13 0c 11 0c 2d 92 } //3
		$a_01_1 = {09 11 07 58 1f 64 5d 13 08 11 08 1f 1e 32 14 } //2
		$a_03_2 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2) >=7
 
}