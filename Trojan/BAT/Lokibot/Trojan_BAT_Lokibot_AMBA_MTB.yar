
rule Trojan_BAT_Lokibot_AMBA_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 13 0e 2b 17 11 0a 11 0e 11 09 11 0e 9a 1f 10 28 ?? 00 00 0a 9c 11 0e 17 d6 13 0e 11 0e 11 09 8e 69 fe 04 13 0f 11 0f 2d db } //3
		$a_03_1 = {13 08 11 08 17 8d 77 00 00 01 25 16 1f 2d 9d 6f ?? 00 00 0a 13 09 11 09 8e 69 8d 5b 00 00 01 13 0a } //2
		$a_01_2 = {45 00 73 00 6d 00 47 00 6a 00 } //1 EsmGj
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}