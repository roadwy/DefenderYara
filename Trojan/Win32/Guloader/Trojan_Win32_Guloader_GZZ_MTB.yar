
rule Trojan_Win32_Guloader_GZZ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_80_0 = {55 70 61 61 76 69 72 6b 65 6c 69 67 65 73 35 } //Upaavirkeliges5  2
		$a_01_1 = {61 70 70 65 61 73 61 62 6c 65 6e 65 73 73 2e 74 78 74 } //2 appeasableness.txt
		$a_01_2 = {42 61 73 69 6c 69 6b 75 6d 65 72 6e 65 73 2e 73 79 73 } //2 Basilikumernes.sys
		$a_01_3 = {67 6c 61 6d 6f 75 72 69 73 65 72 5c 76 69 74 65 2e 67 79 6e } //2 glamouriser\vite.gyn
		$a_01_4 = {7a 61 66 66 72 65 65 5c 74 61 61 65 6e 73 } //2 zaffree\taaens
	condition:
		((#a_80_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}