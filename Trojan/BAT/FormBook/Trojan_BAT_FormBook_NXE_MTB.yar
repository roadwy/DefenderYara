
rule Trojan_BAT_FormBook_NXE_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 32 62 36 62 31 63 32 33 2d 39 38 30 64 2d 34 35 61 39 2d 38 36 30 63 2d 34 37 38 35 64 61 33 36 35 61 64 32 } //1 $2b6b1c23-980d-45a9-860c-4785da365ad2
		$a_01_1 = {57 9f a2 2b 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 92 00 00 00 28 00 00 00 6f 00 00 00 a5 } //1
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}