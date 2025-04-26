
rule Trojan_Win64_IcedID_DJZ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f 10 84 24 b0 01 00 00 f3 0f 7f 84 24 e0 01 00 00 [0-03] 74 } //5
		$a_01_1 = {af 26 00 00 49 83 ce 0f 48 81 ee dd 26 00 00 49 f7 d1 49 f7 c1 45 07 00 00 4d 33 c0 49 81 c9 f5 1c 00 00 48 81 c4 5c 05 00 00 48 0f a4 fa 2a 48 0f a4 d6 04 e4 50 4d 0f ac f4 a9 49 c1 e4 a9 } //1
		$a_01_2 = {48 81 d7 c7 06 00 00 49 81 ea 0d 14 00 00 49 81 dc fb 06 00 00 48 f7 fb 48 69 f6 d4 22 00 00 48 81 dd fb 22 00 00 48 f7 c2 f3 17 00 00 49 13 d4 49 ff cb 48 33 e4 4d 0f a4 de 7c } //1
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}