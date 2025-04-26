
rule Trojan_Win32_Farfli_ASDG_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 08 2b cb 8a 14 01 80 f2 62 88 10 40 4f 75 } //2
		$a_01_1 = {66 75 63 6b 79 6f 75 } //1 fuckyou
		$a_01_2 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 73 63 76 68 6f 73 74 2e 65 78 65 } //1 Program Files\Common Files\scvhost.exe
		$a_01_3 = {5b 50 61 75 73 65 20 42 72 65 61 6b 5d } //1 [Pause Break]
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
rule Trojan_Win32_Farfli_ASDG_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.ASDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff d6 8b 55 fc 8b 45 f8 0f b6 0c 17 0f b6 04 10 03 c8 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 0f b6 04 11 30 83 [0-04] 43 8b 4d f8 81 fb 1c 06 00 00 0f 82 } //2
		$a_01_1 = {8a 0a 32 4d ef 02 4d ef 88 0a c3 8b 45 e4 ff 45 e8 40 c7 45 fc 01 00 00 00 eb } //2
		$a_01_2 = {46 75 63 6b } //1 Fuck
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}