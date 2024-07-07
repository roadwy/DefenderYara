
rule Trojan_BAT_SnakeKeyLogger_RDQ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {38 61 30 32 30 61 35 62 2d 64 38 61 61 2d 34 63 39 66 2d 61 31 65 65 2d 37 33 66 62 36 36 37 38 63 64 62 65 } //1 8a020a5b-d8aa-4c9f-a1ee-73fb6678cdbe
		$a_01_1 = {43 61 65 73 61 72 53 68 69 66 74 } //1 CaesarShift
		$a_01_2 = {46 49 78 7a 70 4b 75 } //1 FIxzpKu
		$a_01_3 = {54 54 54 54 54 54 54 54 54 54 54 54 54 54 54 54 54 54 54 54 54 54 54 54 54 5f 54 4b } //1 TTTTTTTTTTTTTTTTTTTTTTTTT_TK
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}