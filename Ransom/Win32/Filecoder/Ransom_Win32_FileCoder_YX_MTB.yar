
rule Ransom_Win32_FileCoder_YX_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.YX!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 00 6c 00 6c 00 20 00 79 00 6f 00 75 00 72 00 20 00 64 00 61 00 74 00 61 00 20 00 62 00 65 00 65 00 6e 00 20 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 All your data been crypted
		$a_01_1 = {55 00 73 00 65 00 20 00 6d 00 61 00 69 00 6c 00 20 00 74 00 6f 00 20 00 63 00 6f 00 6e 00 74 00 61 00 63 00 74 00 } //1 Use mail to contact
		$a_01_2 = {5c 00 74 00 6f 00 72 00 2e 00 65 00 78 00 65 00 } //1 \tor.exe
		$a_01_3 = {2e 00 6f 00 6e 00 69 00 6f 00 6e 00 } //1 .onion
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}