
rule Trojan_BAT_Remcos_ZMF_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ZMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 06 2b 84 02 8c 01 00 00 1b 03 04 6f ?? 00 00 0a 0b 1b 13 06 38 ?? ff ff ff 06 17 58 0a 20 91 05 00 00 0d 20 14 01 00 00 13 04 20 db 01 00 00 09 19 5b 11 04 59 32 15 11 08 } //6
		$a_03_1 = {1f 10 0b 11 06 20 f8 00 00 00 91 20 85 00 00 00 59 13 04 38 54 ff ff ff 02 28 ?? 00 00 0a 0b 1f 0b 13 04 38 44 ff ff ff 02 28 ?? 00 00 0a 0b 1f 0b 13 04 38 34 ff ff ff 02 28 ?? 00 00 0a 0b 11 05 20 64 01 00 00 94 20 c2 af 00 00 59 13 04 } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}