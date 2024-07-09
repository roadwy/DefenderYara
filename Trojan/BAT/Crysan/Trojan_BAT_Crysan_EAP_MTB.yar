
rule Trojan_BAT_Crysan_EAP_MTB{
	meta:
		description = "Trojan:BAT/Crysan.EAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 11 00 28 ?? 00 00 06 28 ?? 00 00 0a 13 03 38 00 00 00 00 73 ?? 00 00 06 25 11 03 28 ?? 00 00 06 6f ?? 00 00 06 13 02 38 00 00 00 00 dd ?? 00 00 00 26 38 00 00 00 00 dd } //3
		$a_01_1 = {42 00 61 00 77 00 68 00 68 00 77 00 73 00 74 00 75 00 70 00 77 00 66 00 6b 00 62 00 68 00 77 00 70 00 76 00 6b 00 6d 00 77 00 } //2 Bawhhwstupwfkbhwpvkmw
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}