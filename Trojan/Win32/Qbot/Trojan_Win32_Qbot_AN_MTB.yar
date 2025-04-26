
rule Trojan_Win32_Qbot_AN_MTB{
	meta:
		description = "Trojan:Win32/Qbot.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 52 79 5a 69 69 4f 72 6d 66 6c } //2 ARyZiiOrmfl
		$a_01_1 = {41 72 77 33 71 67 } //2 Arw3qg
		$a_01_2 = {42 4d 65 47 6a 54 4b } //2 BMeGjTK
		$a_01_3 = {42 52 57 78 47 57 59 63 57 69 33 } //2 BRWxGWYcWi3
		$a_01_4 = {42 64 54 68 38 75 4b 44 } //2 BdTh8uKD
		$a_01_5 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //2 DllRegisterServer
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}
rule Trojan_Win32_Qbot_AN_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {00 58 35 35 35 00 } //1 堀㔵5
		$a_01_1 = {00 55 7a 6d 61 5f 73 74 72 65 61 6d 5f 66 6c 61 67 73 5f 63 6f 6d 70 61 72 65 00 } //1
		$a_01_2 = {00 55 7a 6d 61 5f 73 74 72 65 61 6d 5f 68 65 61 64 65 72 5f 65 6e 63 6f 64 65 00 } //1
		$a_01_3 = {00 55 7a 6d 61 5f 69 6e 64 65 78 5f 75 6e 63 6f 6d 70 72 65 73 73 65 64 5f 73 69 7a 65 00 } //1 唀浺彡湩敤彸湵潣灭敲獳摥獟穩e
		$a_01_4 = {00 55 7a 6d 61 5f 70 68 79 73 6d 65 6d 00 } //1 唀浺彡桰獹敭m
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}