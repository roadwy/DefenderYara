
rule Trojan_Win32_Redline_GTK_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 1a f7 de 87 f7 f7 05 ?? ?? ?? ?? ac 87 6d 62 7e 05 e8 ?? ?? ?? ?? 48 33 15 ?? ?? ?? ?? c1 eb 01 f7 d6 c1 c3 18 81 ee ?? ?? ?? ?? c1 c2 09 e2 c2 } //10
		$a_03_1 = {b7 8c 76 70 81 f0 a7 1c 73 63 c7 05 ?? ?? ?? ?? 44 96 e9 68 09 3d ?? ?? ?? ?? ff 15 } //10
		$a_01_2 = {73 65 63 75 72 65 2e 6c 6f 67 6d 65 69 6e 2e 63 6f 6d } //1 secure.logmein.com
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=22
 
}