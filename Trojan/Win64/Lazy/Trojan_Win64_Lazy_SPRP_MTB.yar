
rule Trojan_Win64_Lazy_SPRP_MTB{
	meta:
		description = "Trojan:Win64/Lazy.SPRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 83 ec 20 44 8b f9 4c 8d 35 2e f0 fd ff 48 83 cf ff 4d 8b e1 49 8b e8 4c 8b ea 4f 8b 94 fe 50 da 08 00 90 4c 8b 1d 31 70 02 00 4d 33 d3 41 8b cb 83 e1 3f 49 d3 ca 4c 3b d7 0f 84 } //4
		$a_03_1 = {49 8d 4e 30 45 33 c0 ba a0 0f 00 00 e8 90 01 04 48 8b 05 90 01 04 4c 8d 05 90 01 04 48 8b d5 48 c1 fa 06 4c 89 34 03 48 8b c5 83 e0 3f 48 8d 0c c0 49 8b 04 d0 48 8b 4c c8 28 48 83 c1 02 48 83 f9 02 77 06 90 00 } //3
	condition:
		((#a_01_0  & 1)*4+(#a_03_1  & 1)*3) >=7
 
}