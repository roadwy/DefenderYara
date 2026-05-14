
rule Trojan_BAT_Injuke_AYMB_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AYMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 15 06 07 8f ?? 00 00 01 25 47 7e ?? 00 00 04 61 d2 52 07 17 58 0b 07 06 8e 69 32 e5 } //2
		$a_03_1 = {0a 0a 06 17 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 03 04 6f ?? 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 02 16 02 8e 69 28 ?? 00 00 0a 03 16 03 8e 69 28 ?? 00 00 0a 04 16 04 8e 69 28 ?? 00 00 0a 0c de 14 } //5
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*5) >=7
 
}