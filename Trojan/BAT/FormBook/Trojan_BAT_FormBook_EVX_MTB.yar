
rule Trojan_BAT_FormBook_EVX_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EVX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {b7 a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 02 } //1
		$a_01_1 = {24 33 33 66 65 35 63 33 32 2d 64 62 36 61 2d 34 64 37 61 2d 61 64 64 63 2d 65 31 64 30 64 38 35 38 38 66 62 31 } //1 $33fe5c32-db6a-4d7a-addc-e1d0d8588fb1
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_3 = {54 6f 6b 65 6e 69 7a 65 72 2e 64 6c 6c } //1 Tokenizer.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}