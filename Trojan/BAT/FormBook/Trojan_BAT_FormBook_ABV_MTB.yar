
rule Trojan_BAT_FormBook_ABV_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 15 02 00 09 08 00 00 00 00 00 00 00 00 00 00 01 00 00 00 2d 00 00 00 06 00 00 00 6e 00 00 00 13 00 00 00 02 00 00 00 2e 00 00 00 } //5
		$a_01_1 = {59 76 76 71 72 2e 65 78 65 } //1 Yvvqr.exe
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}