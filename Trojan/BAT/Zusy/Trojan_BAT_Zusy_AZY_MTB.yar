
rule Trojan_BAT_Zusy_AZY_MTB{
	meta:
		description = "Trojan:BAT/Zusy.AZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 16 0c 2b 1a 06 08 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 16 61 d2 81 ?? 00 00 01 08 17 58 0c 08 06 8e 69 32 e0 07 06 28 ?? 00 00 0a 07 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Zusy_AZY_MTB_2{
	meta:
		description = "Trojan:BAT/Zusy.AZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_03_0 = {0b 07 16 02 a2 73 07 00 00 0a 0c 28 ?? 00 00 0a 28 ?? 00 00 0a 1f 5c 6f ?? 00 00 0a 17 58 6f ?? 00 00 0a 19 17 73 0b 00 00 0a 0d 09 7e 01 00 00 04 6a 6f } //3
		$a_01_1 = {16 0a 2b 27 02 7e 02 00 00 04 02 7b 03 00 00 04 d2 03 04 06 58 e0 91 61 95 02 7b 03 00 00 04 1e 64 61 7d 03 00 00 04 06 17 58 0a 06 05 37 d5 } //2
		$a_01_2 = {78 70 61 63 6b 21 } //1 xpack!
		$a_01_3 = {73 4d 61 74 63 68 44 65 63 6f 64 65 72 73 } //1 sMatchDecoders
		$a_01_4 = {73 52 65 70 44 65 63 6f 64 65 72 73 } //1 sRepDecoders
		$a_01_5 = {73 52 65 70 47 30 44 65 63 6f 64 65 72 73 } //1 sRepG0Decoders
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}