
rule Trojan_Win32_LtuoKoo_ZZ{
	meta:
		description = "Trojan:Win32/LtuoKoo.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc9 00 ffffffc9 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {45 33 c9 45 33 c0 8d 4a 0e ff d7 41 b9 01 00 00 00 4c 8b c0 48 8b ce 4c 8b e8 41 8d 51 2f ff } //100
		$a_01_2 = {48 b8 83 2d d8 82 2d d8 82 2d 48 8b f7 48 f7 e7 33 db 48 c1 ea 04 48 6b ca 5a 48 2b f1 48 83 c6 0a } //100
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100) >=201
 
}