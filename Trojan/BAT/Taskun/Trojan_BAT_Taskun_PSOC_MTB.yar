
rule Trojan_BAT_Taskun_PSOC_MTB{
	meta:
		description = "Trojan:BAT/Taskun.PSOC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 72 86 2d 00 70 6f 90 01 03 0a 72 96 2d 00 70 72 9a 2d 00 70 6f 90 01 03 0a 28 90 01 03 2b 28 90 01 03 2b 73 90 01 03 0a 0b 07 17 8d 57 00 00 01 25 16 1f 2d 9d 6f 90 01 03 0a 0c 08 8e 69 8d a0 00 00 01 0d 16 13 07 2b 15 09 11 07 08 11 07 9a 1f 10 28 90 01 03 0a 9c 11 07 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}