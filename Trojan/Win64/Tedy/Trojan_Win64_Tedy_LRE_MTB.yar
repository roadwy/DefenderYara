
rule Trojan_Win64_Tedy_LRE_MTB{
	meta:
		description = "Trojan:Win64/Tedy.LRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c8 49 8b d1 80 e1 07 c0 e1 03 48 d3 ea 41 30 14 00 48 ff c0 48 83 f8 02 } //20
		$a_03_1 = {80 79 07 00 74 ?? 80 31 99 80 71 01 ad 80 71 02 29 80 71 03 5d 80 71 04 15 80 71 05 03 80 71 06 65 c6 41 07 00 } //10
		$a_03_2 = {80 79 05 00 74 ?? 80 31 3d 80 71 01 fb 80 71 02 4d 80 71 03 09 80 71 04 af c6 41 05 00 } //5
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*10+(#a_03_2  & 1)*5) >=30
 
}