
rule Trojan_BAT_FormBook_FOAA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.FOAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 02 7b 90 01 01 00 00 04 a2 25 17 02 7b 90 01 01 00 00 04 a2 25 18 02 7b 90 01 01 00 00 04 a2 25 19 02 90 00 } //1
		$a_01_1 = {79 00 37 00 31 00 72 00 33 00 53 00 4d 00 45 00 35 00 77 00 66 00 43 00 68 00 50 00 37 00 75 00 6a 00 45 00 70 00 2b 00 7a 00 56 00 48 00 } //1 y71r3SME5wfChP7ujEp+zVH
		$a_01_2 = {55 00 47 00 58 00 6b 00 5a 00 55 00 6d 00 45 00 } //1 UGXkZUmE
		$a_01_3 = {4c 00 6c 00 4a 00 6c 00 5a 00 6d 00 78 00 6c 00 59 00 33 00 52 00 70 00 62 00 32 00 34 00 } //1 LlJlZmxlY3Rpb24
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}