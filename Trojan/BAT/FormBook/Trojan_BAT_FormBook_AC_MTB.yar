
rule Trojan_BAT_FormBook_AC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {b6 00 b6 00 60 00 6c 25 70 00 46 00 55 00 75 00 67 00 88 25 88 25 88 25 88 25 88 25 88 25 88 25 88 25 88 25 88 25 57 00 49 00 50 00 6f 00 43 00 59 00 76 00 49 00 67 00 38 00 88 25 88 25 38 00 69 00 } //1
		$a_01_1 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}