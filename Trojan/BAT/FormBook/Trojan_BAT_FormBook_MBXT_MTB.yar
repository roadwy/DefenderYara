
rule Trojan_BAT_FormBook_MBXT_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 91 04 06 28 ?? 00 00 0a 05 6f ?? 00 00 0a 8e 69 5d 91 61 d2 9c 00 06 17 58 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_MBXT_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 73 64 61 64 73 61 64 73 61 64 73 61 64 61 } //1 asdadsadsadsada
		$a_01_1 = {63 63 63 63 63 63 63 63 63 63 32 31 32 33 31 32 33 } //1 cccccccccc2123123
		$a_01_2 = {4b 00 6f 00 72 00 65 00 61 00 6e 00 43 00 68 00 65 00 73 00 73 00 } //1 KoreanChess
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 73 } //1 GetMethods
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_BAT_FormBook_MBXT_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 11 05 11 06 6f ?? 00 00 0a 13 07 08 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 08 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 08 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 07 08 } //3
		$a_01_1 = {4c 00 6f 00 61 00 64 00 } //2 Load
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_BAT_FormBook_MBXT_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {34 00 38 00 46 00 57 00 37 00 43 00 34 00 38 00 45 00 46 00 42 00 48 00 35 00 38 00 43 00 39 00 5a 00 46 00 35 00 37 00 31 00 34 00 } //10 48FW7C48EFBH58C9ZF5714
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //3 InvokeMember
		$a_01_2 = {47 65 74 4f 62 6a 65 63 74 } //2 GetObject
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=16
 
}