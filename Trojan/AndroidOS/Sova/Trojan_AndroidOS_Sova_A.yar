
rule Trojan_AndroidOS_Sova_A{
	meta:
		description = "Trojan:AndroidOS/Sova.A,SIGNATURE_TYPE_DEXHSTR_EXT,0f 00 0f 00 09 00 00 "
		
	strings :
		$a_00_0 = {73 74 61 72 74 64 64 6f 73 } //4 startddos
		$a_00_1 = {73 63 61 6e 69 6e 6a 65 63 74 } //4 scaninject
		$a_00_2 = {66 6f 72 69 6e 6a 65 63 74 2e 70 68 70 } //4 forinject.php
		$a_00_3 = {73 74 6f 70 68 69 64 65 6e 73 6d 73 } //2 stophidensms
		$a_00_4 = {73 74 61 72 74 68 69 64 65 6e 70 75 73 68 } //2 starthidenpush
		$a_00_5 = {73 74 65 61 6c 65 72 } //1 stealer
		$a_00_6 = {64 65 6c 62 6f 74 } //1 delbot
		$a_00_7 = {73 74 61 72 74 6b 65 79 6c 6f 67 } //1 startkeylog
		$a_00_8 = {73 65 6e 64 5f 63 6f 6f 6b 69 65 } //1 send_cookie
	condition:
		((#a_00_0  & 1)*4+(#a_00_1  & 1)*4+(#a_00_2  & 1)*4+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=15
 
}