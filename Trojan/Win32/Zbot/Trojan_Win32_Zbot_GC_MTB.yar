
rule Trojan_Win32_Zbot_GC_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 8b 4d fc 33 c6 33 ce 8d 8c 08 b6 4a ca 0e 8b 45 f8 33 d2 f7 f1 8b 45 f4 8b 4d fc 33 c6 33 ce 2b c1 3b d0 0f 85 3b 00 00 00 } //10
		$a_01_1 = {73 63 78 68 67 66 65 65 55 64 67 71 5c 63 65 6b 76 65 6a 65 2e 70 64 62 } //1 scxhgfeeUdgq\cekveje.pdb
		$a_80_2 = {49 44 55 6f 69 6a 6b 4e 44 2e 74 78 74 } //IDUoijkND.txt  1
		$a_01_3 = {71 77 51 66 68 73 64 4b 53 6e 44 } //1 qwQfhsdKSnD
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}