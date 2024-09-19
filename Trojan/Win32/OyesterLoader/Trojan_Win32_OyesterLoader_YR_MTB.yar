
rule Trojan_Win32_OyesterLoader_YR_MTB{
	meta:
		description = "Trojan:Win32/OyesterLoader.YR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 68 70 f5 32 10 6a 01 6a 00 ff 15 d8 c0 29 10 } //1
		$a_01_1 = {70 6f 73 74 6d 61 6e 5c 44 65 73 6b 74 6f 70 5c 4e 5a 54 5c 50 72 6f 6a 65 63 74 44 5f 63 70 70 72 65 73 74 } //1 postman\Desktop\NZT\ProjectD_cpprest
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}