
rule Trojan_BAT_KingRAT_PLIDH_MTB{
	meta:
		description = "Trojan:BAT/KingRAT.PLIDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 06 08 6f ?? 00 00 0a 11 06 18 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 13 07 02 7e ?? 00 00 04 07 20 ad 01 00 00 59 97 29 ?? 00 00 11 0a 11 07 06 16 06 8e 20 4e 12 d7 6b 80 ?? 00 00 04 b7 6f ?? 00 00 0a 28 ?? 00 00 06 13 05 11 05 13 08 00 20 e1 2a 79 2f 80 ?? 00 00 04 11 08 2a } //10
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}