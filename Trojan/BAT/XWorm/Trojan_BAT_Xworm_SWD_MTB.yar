
rule Trojan_BAT_Xworm_SWD_MTB{
	meta:
		description = "Trojan:BAT/Xworm.SWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 08 6f 07 00 00 0a 0d 09 14 28 ?? 00 00 0a 2c 44 72 d4 aa 01 70 09 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 09 6f ?? 00 00 0a 8e 69 2c 16 17 8d 01 00 00 01 13 07 11 07 16 16 8d 05 00 00 01 a2 11 07 2b 01 14 13 04 09 14 11 04 6f ?? 00 00 0a 26 2b 13 72 fc aa 01 70 72 5c ab 01 70 16 1f 10 28 ?? 00 00 0a 26 de 23 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}