
rule Trojan_BAT_Redline_NEE_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 07 6f 25 00 00 0a 03 07 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 0c 06 72 ?? ?? ?? 70 08 28 3a 01 00 0a 6f 3b 01 00 0a 26 07 17 58 0b 07 02 6f ?? ?? ?? 0a 32 ca } //1
		$a_01_1 = {43 00 68 00 69 00 6c 00 62 00 6c 00 61 00 69 00 6e 00 } //1 Chilblain
		$a_01_2 = {47 00 61 00 73 00 64 00 6c 00 39 00 34 00 6a 00 6c 00 61 00 6a 00 73 00 64 00 65 00 74 00 44 00 65 00 76 00 61 00 73 00 64 00 6c 00 39 00 34 00 6a 00 6c 00 61 00 6a 00 73 00 64 00 69 00 63 00 65 00 43 00 61 00 70 00 61 00 73 00 64 00 6c 00 39 00 34 00 6a 00 6c 00 61 00 6a 00 73 00 64 00 73 00 } //1 Gasdl94jlajsdetDevasdl94jlajsdiceCapasdl94jlajsds
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}