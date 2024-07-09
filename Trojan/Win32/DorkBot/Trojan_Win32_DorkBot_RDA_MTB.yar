
rule Trojan_Win32_DorkBot_RDA_MTB{
	meta:
		description = "Trojan:Win32/DorkBot.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {89 d1 29 c1 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af c2 29 c1 89 c8 89 c2 8b 45 dc 01 d0 0f b6 00 31 f0 88 03 } //2
		$a_01_1 = {4c 64 72 46 69 6e 64 52 65 73 6f 75 72 63 65 5f 55 } //1 LdrFindResource_U
		$a_01_2 = {4c 64 72 41 63 63 65 73 73 52 65 73 6f 75 72 63 65 } //1 LdrAccessResource
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_4 = {73 00 63 00 2e 00 65 00 78 00 65 00 } //1 sc.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}