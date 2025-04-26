
rule Trojan_BAT_DarkComet_AAEH_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AAEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 6f ?? 00 00 0a 00 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 00 08 18 6f ?? 00 00 0a 00 08 18 6f ?? 00 00 0a 00 08 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0d 08 } //3
		$a_01_1 = {4b 00 4b 00 4b 00 4b 00 4b 00 4b 00 4b 00 4b 00 4b 00 4c 00 4c 00 4c 00 4c 00 4c 00 4c 00 4c 00 4d 00 4d 00 4d 00 4d 00 50 00 50 00 50 00 50 00 4f 00 4f 00 4f 00 4f 00 } //1 KKKKKKKKKLLLLLLLMMMMPPPPOOOO
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}