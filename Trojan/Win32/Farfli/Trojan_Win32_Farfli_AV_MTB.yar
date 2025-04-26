
rule Trojan_Win32_Farfli_AV_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {33 c9 8a 1c 38 8b d1 81 e2 ff ff 00 00 8a 54 54 0c 32 da 41 88 1c 38 40 3b c6 72 de } //2
		$a_01_1 = {33 f6 8a 04 39 8b d6 81 e2 ff ff 00 00 2c 7a 8a 54 54 18 32 d0 46 88 14 39 41 3b cd 7c dc } //2
		$a_01_2 = {56 69 72 74 75 61 6c 42 6f 78 } //1 VirtualBox
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_4 = {25 73 5c 25 73 2e 65 78 65 } //1 %s\%s.exe
		$a_01_5 = {53 65 72 76 69 63 65 4d 61 69 6e } //1 ServiceMain
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}