
rule Backdoor_Linux_Mirai_EQ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EQ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {9c 50 9f e5 9c 30 9f e5 05 50 8f e0 03 40 95 e7 94 30 9f e5 ?? ?? ?? ?? 03 10 95 e7 04 20 a0 e1 88 30 9f e5 00 60 a0 e1 0d 00 a0 e1 03 c0 95 e7 0f e0 a0 e1 ?? ?? ?? ?? 74 30 9f e5 04 00 a0 e1 03 c0 95 e7 0f e0 a0 e1 1c ff 2f e1 64 30 9f e5 03 20 95 e7 02 30 a0 e1 00 00 53 e3 06 00 a0 11 0f e0 a0 11 12 ff 2f 11 4c 30 9f e5 0d 00 a0 e1 01 10 a0 e3 ?? ?? ?? ?? 0f e0 a0 e1 ?? ?? ?? ?? ad 04 00 eb 34 30 9f e5 03 20 85 e0 02 30 a0 e1 00 00 53 e3 0f e0 a0 11 12 ff 2f 11 06 00 a0 e1 53 06 00 eb } //1
		$a_00_1 = {00 30 d3 05 04 28 a0 e1 0c c0 83 00 0e 38 a0 e1 22 28 a0 e1 23 38 a0 e1 02 30 83 e0 24 38 83 e0 2e 38 83 e0 05 30 83 e0 09 20 d0 e5 0c 30 83 e0 02 04 83 e0 02 00 00 ea } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}