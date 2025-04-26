
rule Trojan_Win32_Redcap_AMAA_MTB{
	meta:
		description = "Trojan:Win32/Redcap.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {48 3a 5c 50 4d 53 5c 5f 41 55 70 64 61 74 65 5c 48 61 6e 43 61 70 74 75 72 65 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 41 67 65 6e 74 2e 70 64 62 } //H:\PMS\_AUpdate\HanCapture\bin\Release\Agent.pdb  1
		$a_80_1 = {42 6f 67 75 73 20 4a 50 45 47 20 63 6f 6c 6f 72 73 70 61 63 65 } //Bogus JPEG colorspace  1
		$a_80_2 = {42 6f 67 75 73 20 48 75 66 66 6d 61 6e 20 74 61 62 6c 65 20 64 65 66 69 6e 69 74 69 6f 6e } //Bogus Huffman table definition  1
		$a_80_3 = {53 6f 72 72 79 2c 20 74 68 65 72 65 20 61 72 65 20 6c 65 67 61 6c 20 72 65 73 74 72 69 63 74 69 6f 6e 73 } //Sorry, there are legal restrictions  1
		$a_80_4 = {57 72 6f 6e 67 20 4a 50 45 47 20 6c 69 62 72 61 72 79 } //Wrong JPEG library  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}