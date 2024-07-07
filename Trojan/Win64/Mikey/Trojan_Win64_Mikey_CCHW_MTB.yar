
rule Trojan_Win64_Mikey_CCHW_MTB{
	meta:
		description = "Trojan:Win64/Mikey.CCHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 0f 44 c5 89 6c 24 28 45 33 c9 48 89 6c 24 20 33 d2 48 8d 4c 24 60 ff 15 } //5
		$a_01_1 = {8b 54 24 40 4c 8b cf 44 8b c6 48 8b cb ff 15 } //5
		$a_01_2 = {6d 6f 64 75 6c 65 73 5c 77 69 6e 33 32 63 72 79 70 74 65 64 5c 73 72 63 5c 77 69 6e 33 32 64 65 63 72 79 70 74 } //1 modules\win32crypted\src\win32decrypt
		$a_01_3 = {6d 6f 64 75 6c 65 73 5c 77 69 6e 64 6f 33 32 6c 69 62 5c 73 72 63 5c 77 69 6e 64 6f 33 32 6c 69 62 } //1 modules\windo32lib\src\windo32lib
		$a_01_4 = {6d 6f 64 75 6c 65 73 5c 6d 61 78 69 6d 75 6d 70 73 77 64 5c 73 72 63 5c 6d 61 78 69 6d 75 6d 70 73 77 64 } //1 modules\maximumpswd\src\maximumpswd
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=11
 
}