
rule Trojan_BAT_Typhon_PVA_MTB{
	meta:
		description = "Trojan:BAT/Typhon.PVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {13 1a 11 1a 1f 10 64 d1 13 15 11 15 d2 13 37 11 15 1e 63 d1 13 15 11 20 11 09 91 13 22 11 20 11 09 11 22 11 2a 61 19 11 1e 58 61 11 37 61 d2 9c 11 09 17 58 13 09 11 22 13 1e 11 09 } //5
		$a_01_1 = {11 2b 11 12 11 16 11 12 91 9d 17 11 12 58 13 12 11 12 11 0c 32 ea 11 2b } //2
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=8
 
}