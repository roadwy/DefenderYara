
rule Trojan_BAT_Formbook_SJN_MTB{
	meta:
		description = "Trojan:BAT/Formbook.SJN!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 44 00 00 0a 72 a5 03 00 70 72 a9 03 00 70 6f 45 00 00 0a 72 b1 03 00 70 72 b5 03 00 70 6f 45 00 00 0a 72 b9 03 00 70 72 bd 03 00 70 6f 45 00 00 0a 0b 07 72 c1 03 00 70 18 17 8d 10 00 00 01 25 16 72 bd 03 00 70 a2 } //1
		$a_01_1 = {28 48 00 00 0a d2 6f 49 00 00 0a 00 11 08 17 58 13 08 11 08 08 8e 69 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}