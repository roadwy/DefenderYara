
rule Trojan_Win32_Potatohttploader_D{
	meta:
		description = "Trojan:Win32/Potatohttploader.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {54 56 71 51 41 41 4d 41 41 41 41 45 41 41 41 41 2f 2f 38 41 41 4c 67 } //TVqQAAMAAAAEAAAA//8AALg  1
		$a_80_1 = {48 74 74 70 43 6f 72 65 2e 41 67 65 6e 74 } //HttpCore.Agent  1
		$a_80_2 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d 2f 44 65 66 61 75 6c 74 } //https://www.example.com/Default  1
		$a_80_3 = {5c 50 72 6f 67 72 61 6d } //\Program  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}