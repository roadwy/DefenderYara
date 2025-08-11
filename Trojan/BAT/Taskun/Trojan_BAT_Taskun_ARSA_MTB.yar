
rule Trojan_BAT_Taskun_ARSA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 08 5a 20 ff 00 00 00 5d 13 09 11 09 16 30 05 11 09 65 2b 02 11 09 13 09 02 11 05 11 08 6f ?? 00 00 0a 13 0a 11 05 11 08 58 18 5d 16 fe 01 13 0b 11 0b 2d 07 11 0b 16 fe 01 2b 01 17 13 0e 11 0e 2c 02 00 00 04 03 6f ?? 00 00 0a 59 } //5
		$a_03_1 = {01 25 16 12 0a 28 ?? 00 00 0a 9c 25 17 12 0a 28 ?? 00 00 0a 9c 25 18 12 0a 28 ?? 00 00 0a 9c } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}