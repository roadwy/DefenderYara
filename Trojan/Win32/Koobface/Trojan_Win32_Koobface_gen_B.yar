
rule Trojan_Win32_Koobface_gen_B{
	meta:
		description = "Trojan:Win32/Koobface.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {05 00 ff ff ff 56 50 53 ff 15 ?? ?? ?? ?? 8d 45 08 56 50 68 00 01 00 00 } //1
		$a_03_1 = {59 0f 84 35 04 00 00 8b 3d ?? ?? ?? ?? 6a 3d ff 75 0c ff d7 } //1
		$a_01_2 = {75 70 74 69 6d 65 3d 25 6c 64 26 76 3d } //1 uptime=%ld&v=
		$a_01_3 = {77 65 62 73 72 76 } //1 websrv
		$a_01_4 = {62 6c 64 6f 25 6c 64 2e 74 6d 70 00 } //1
		$a_01_5 = {3f 6e 65 77 76 65 72 } //1 ?newver
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}