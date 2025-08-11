
rule Trojan_Win64_Shellcode_MX_MTB{
	meta:
		description = "Trojan:Win64/Shellcode.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 31 ca 48 31 c9 48 ff c8 88 02 48 31 fa 48 ff c3 48 39 f3 } //1
		$a_01_1 = {68 00 65 00 6c 00 6c 00 6f 00 5f 00 69 00 6d 00 5f 00 73 00 69 00 69 00 } //1 hello_im_sii
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}