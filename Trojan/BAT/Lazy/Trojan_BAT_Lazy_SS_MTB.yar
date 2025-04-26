
rule Trojan_BAT_Lazy_SS_MTB{
	meta:
		description = "Trojan:BAT/Lazy.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {5f 63 72 79 70 74 65 64 } //2 _crypted
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {62 37 64 38 66 35 30 33 2d 38 66 34 30 2d 34 32 65 35 2d 62 64 65 33 2d 66 39 35 31 32 61 34 61 36 64 31 35 } //1 b7d8f503-8f40-42e5-bde3-f9512a4a6d15
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}