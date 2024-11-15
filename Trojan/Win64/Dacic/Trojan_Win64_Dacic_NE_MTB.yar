
rule Trojan_Win64_Dacic_NE_MTB{
	meta:
		description = "Trojan:Win64/Dacic.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 ff ca b8 cd cc cc cc 41 f7 e0 c1 ea 03 0f b6 c2 c0 e0 02 8d 0c 10 02 c9 44 2a c1 41 80 c0 30 45 88 02 44 8b c2 85 d2 75 d6 } //3
		$a_03_1 = {f7 e9 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 0f be c2 6b d0 ?? 0f b6 c1 2a c2 04 30 41 30 ?? ff c1 4d 8d 40 ?? 83 f9 1d 7c } //2
		$a_02_2 = {5c 00 78 00 36 00 34 00 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 [0-2f] 2e 00 70 00 64 00 62 00 } //1
		$a_02_3 = {5c 78 36 34 5c 52 65 6c 65 61 73 65 5c [0-2f] 2e 70 64 62 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=6
 
}