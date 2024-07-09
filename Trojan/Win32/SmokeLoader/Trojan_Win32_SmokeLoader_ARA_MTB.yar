
rule Trojan_Win32_SmokeLoader_ARA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 8c 30 4b 13 01 00 a1 ?? ?? ?? ?? 88 0c 30 81 fa ?? ?? ?? ?? 75 3a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_SmokeLoader_ARA_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {a1 10 c9 83 00 8a 84 38 3b 2d 0b 00 8b 0d 08 bf 83 00 88 04 39 81 3d 0c c9 83 00 92 02 00 00 75 0d 68 54 2e 40 00 56 56 ff 15 7c 10 40 00 47 3b 3d 0c c9 83 00 72 c9 } //2
		$a_01_1 = {70 61 67 65 68 6f 6b 69 7a 61 6c 6f 62 75 73 65 62 69 79 75 78 } //2 pagehokizalobusebiyux
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}