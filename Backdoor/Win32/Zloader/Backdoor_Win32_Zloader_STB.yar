
rule Backdoor_Win32_Zloader_STB{
	meta:
		description = "Backdoor:Win32/Zloader.STB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_01_0 = {02 05 25 38 0a 10 0f a4 df 01 89 44 24 1c 03 db a2 1e 38 0a 10 8b 44 24 14 81 c3 81 bf fe ff 83 d7 ff } //1
		$a_01_1 = {75 70 81 78 14 20 05 93 19 74 12 81 78 14 21 05 93 19 74 09 81 78 14 22 05 93 19 } //10
		$a_03_2 = {02 c1 8a d1 0f b6 c0 6b c0 ?? 2a d0 80 ea } //1
		$a_01_3 = {81 c1 40 25 ff ff 0f b7 c0 03 d1 0f b6 0d a6 98 0a 10 89 44 24 18 0f b6 05 a8 98 0a 10 2b c8 81 f9 c3 01 00 00 74 16 a1 b8 98 0a 10 bb 5b 00 00 00 } //2
		$a_01_4 = {81 f7 6e 74 65 6c 8b 45 e8 35 69 6e 65 49 89 45 f8 8b 45 e0 35 47 65 6e 75 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_03_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=16
 
}