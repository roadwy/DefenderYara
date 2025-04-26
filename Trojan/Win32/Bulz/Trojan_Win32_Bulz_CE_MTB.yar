
rule Trojan_Win32_Bulz_CE_MTB{
	meta:
		description = "Trojan:Win32/Bulz.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 20 61 6d 20 76 69 72 75 73 21 20 46 75 63 6b 20 79 6f 75 } //1 I am virus! Fuck you
		$a_01_1 = {54 68 65 20 73 6f 66 74 77 61 72 65 20 79 6f 75 20 6a 75 73 74 20 65 78 65 63 75 74 65 64 20 69 73 20 63 6f 6e 73 69 64 65 72 65 64 20 6d 61 6c 77 61 72 65 } //1 The software you just executed is considered malware
		$a_01_2 = {54 68 69 73 20 54 72 6f 6a 61 6e 20 77 69 6c 6c 20 68 61 72 6d 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 } //1 This Trojan will harm your computer
		$a_01_3 = {59 6f 75 20 61 72 65 20 69 6e 66 65 63 74 65 64 20 4c 4d 41 4f } //1 You are infected LMAO
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}