
rule Trojan_BAT_FormBook_AFR_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 6a 13 09 2b 53 00 11 09 1f 16 6a 5d 13 0a 07 11 09 07 8e 69 6a 5d d4 07 11 09 07 8e 69 6a 5d d4 91 08 11 0a 69 6f ?? 01 00 0a 61 07 11 09 17 6a 58 07 8e 69 6a 5d d4 91 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFR_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0a 11 04 20 ca 00 00 00 91 20 dd 00 00 00 59 0d 2b c3 02 03 06 04 05 28 ?? ?? ?? 06 06 17 58 0a 19 0d 2b b1 } //2
		$a_03_1 = {02 03 04 20 a4 02 00 00 20 a6 02 00 00 28 ?? 00 00 2b 0a 0e 04 05 6f ?? 00 00 0a 59 0b 19 0d 2b c5 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_AFR_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 6a 00 07 11 04 93 13 05 11 05 7e 40 00 00 04 8e 69 2f 0d 7e 40 00 00 04 11 05 93 16 fe 01 2b 01 17 13 06 11 06 2c 08 00 06 17 58 0a 00 2b 35 00 06 16 fe 02 13 07 11 07 2c 11 00 03 07 11 04 06 59 06 6f ?? ?? ?? 0a 26 16 0a 00 03 1f 5c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AFR_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.AFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 19 11 06 5a 6f ?? ?? ?? 0a 13 07 11 07 1f 39 fe 02 13 09 11 09 2c 0d 11 07 1f 41 59 1f 0a 58 d1 13 07 2b 08 11 07 1f 30 59 d1 13 07 06 19 11 06 5a 17 58 6f ?? ?? ?? 0a 13 08 11 08 1f 39 fe 02 13 0a 11 0a 2c 0d 11 08 1f 41 59 1f 0a 58 d1 13 08 2b 08 11 08 1f 30 59 d1 13 08 08 11 06 1f 10 11 07 5a 11 08 58 d2 9c 00 11 06 17 58 13 06 11 06 07 fe 04 13 0b 11 0b 2d 84 } //2
		$a_01_1 = {45 00 6e 00 67 00 69 00 6e 00 65 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 50 00 } //1 Engine.ResourceP
		$a_01_2 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}