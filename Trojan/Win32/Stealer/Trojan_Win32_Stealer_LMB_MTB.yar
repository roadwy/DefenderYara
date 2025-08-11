
rule Trojan_Win32_Stealer_LMB_MTB{
	meta:
		description = "Trojan:Win32/Stealer.LMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2d 00 2d 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 c2 0f b6 44 05 00 89 fe 21 c6 31 c7 8d 04 77 01 c1 0f b6 74 15 01 01 c6 01 f1 0f b6 44 15 02 01 f0 01 c1 0f b6 74 15 03 89 c7 21 f7 31 f0 8d 04 78 01 c1 0f b6 74 15 04 01 c6 01 f1 0f b6 44 15 05 01 f0 01 c1 0f b6 74 15 06 01 c6 01 f1 0f b6 7c 15 07 01 f7 01 f9 } //20
		$a_01_1 = {89 ca 21 c2 01 c8 29 d0 89 d1 01 c9 f7 d1 01 d1 31 c1 f7 d1 21 c1 89 0c 24 8b 04 24 05 24 d1 ee cb 0f b6 c0 83 c4 0c } //20
		$a_01_2 = {0f b6 3c 31 89 c3 c1 eb 04 31 f8 83 e0 0f 33 1c 85 fc e6 44 00 89 d8 c1 e8 04 89 dd f7 d5 83 cd 0f 01 eb 43 c1 ef 04 31 df 33 04 bd fc e6 44 00 46 39 f2 } //5
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*20+(#a_01_2  & 1)*5) >=45
 
}