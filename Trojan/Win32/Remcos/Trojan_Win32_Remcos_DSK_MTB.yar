
rule Trojan_Win32_Remcos_DSK_MTB{
	meta:
		description = "Trojan:Win32/Remcos.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 7c 24 24 8a 54 24 14 8a 44 24 16 0a 44 24 12 88 14 3e 83 25 90 01 04 00 8a 54 24 15 88 54 3e 01 81 3d 90 01 04 d8 01 00 00 88 44 24 16 75 90 00 } //2
		$a_02_1 = {8a 54 24 15 33 c9 8a 44 24 17 0a 44 24 13 88 14 3e 8a 54 24 16 89 0d 90 01 04 88 54 3e 01 81 3d 90 01 04 d8 01 00 00 88 44 24 17 75 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}