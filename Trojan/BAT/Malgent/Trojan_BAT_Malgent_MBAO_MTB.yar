
rule Trojan_BAT_Malgent_MBAO_MTB{
	meta:
		description = "Trojan:BAT/Malgent.MBAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 d4 27 00 00 9d 19 0c 2b a8 06 74 0b 00 00 1b 1c 20 58 35 00 00 9d 06 75 0b 00 00 1b 16 20 d8 33 00 00 9d 1a 0c 2b 8a 06 74 0b 00 00 1b 1d 20 f2 38 00 00 } //1
		$a_01_1 = {58 6e 36 34 43 71 6b 39 47 48 62 33 38 4d 63 41 72 31 77 32 00 00 05 01 00 01 00 00 29 01 00 24 34 62 37 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}