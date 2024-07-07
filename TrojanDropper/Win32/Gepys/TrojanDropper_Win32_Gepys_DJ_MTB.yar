
rule TrojanDropper_Win32_Gepys_DJ_MTB{
	meta:
		description = "TrojanDropper:Win32/Gepys.DJ!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 7d 08 8a 0c 37 89 df 46 d3 e7 89 7d d8 8b 7d d4 03 4d d8 88 0c 07 8b 4d d0 01 f1 39 d0 0f 44 f1 40 3b 45 f0 } //1
		$a_01_1 = {01 f0 f7 f1 8b 45 e4 88 d9 d3 e0 05 c3 77 03 00 d3 e8 b9 80 0d 01 00 89 d6 89 15 } //1
		$a_01_2 = {8b 7d 08 8a 0c 37 46 8b 7d ec 01 d9 3b 45 d8 88 0c 07 8d 0c 16 0f 44 f1 40 3b 45 f0 } //1
		$a_01_3 = {f7 f1 88 d9 d3 6d ec 8b 4d ec 81 c1 3f 9c 04 00 d3 e3 8d 04 0b b9 bb ff 00 00 89 d6 89 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}