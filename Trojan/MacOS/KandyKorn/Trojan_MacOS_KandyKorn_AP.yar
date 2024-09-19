
rule Trojan_MacOS_KandyKorn_AP{
	meta:
		description = "Trojan:MacOS/KandyKorn.AP,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 61 70 70 6c 65 2e 73 61 66 61 72 69 2e 63 6b } //2 com.apple.safari.ck
		$a_00_1 = {73 77 5f 76 65 72 73 } //1 sw_vers
		$a_00_2 = {2f 74 6d 70 2f 74 65 6d 70 58 58 58 58 } //1 /tmp/tempXXXX
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}