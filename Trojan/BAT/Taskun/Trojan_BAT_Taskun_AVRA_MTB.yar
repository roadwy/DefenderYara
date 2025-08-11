
rule Trojan_BAT_Taskun_AVRA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AVRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 07 11 0b 6f ?? 00 00 0a 13 0c 11 06 11 05 6f ?? 00 00 0a 59 13 0d 11 0d 19 fe 04 16 fe 01 13 0e 11 0e 2c 55 00 19 8d ?? 00 00 01 25 16 12 0c 28 ?? 00 00 0a 9c 25 17 12 0c 28 ?? 00 00 0a 9c 25 18 12 0c 28 ?? 00 00 0a 9c 13 0f 08 } //5
		$a_03_1 = {11 0d 16 fe 02 13 11 11 11 2c 4e 00 19 8d ?? 00 00 01 25 16 12 0c 28 ?? 00 00 0a 9c 25 17 12 0c 28 ?? 00 00 0a 9c 25 18 12 0c 28 ?? 00 00 0a 9c } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}