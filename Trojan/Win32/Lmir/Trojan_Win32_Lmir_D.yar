
rule Trojan_Win32_Lmir_D{
	meta:
		description = "Trojan:Win32/Lmir.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_03_0 = {74 1b 56 8b fe bb 90 01 04 83 fb 00 74 08 ac c0 c8 90 01 01 aa 4b eb f3 5e 66 c7 06 4d 5a 90 00 } //2
		$a_03_1 = {8b fe ac 0a c0 74 05 34 8b aa eb f6 47 ac 0a c0 75 f5 c3 90 09 08 00 2f 74 17 be 90 00 } //1
		$a_03_2 = {74 62 81 3e 47 49 44 3a 75 f2 83 c6 05 6a 0d 56 8d 85 90 01 02 ff ff 50 e8 90 00 } //1
		$a_01_3 = {54 58 54 3d 49 44 3a 25 73 2c 50 61 73 73 3a 25 73 2c 4e 6f 3a 25 73 2c 53 4e 3a 25 73 2c 4d 42 3a 25 73 00 } //1 塔㵔䑉┺ⱳ慐獳┺ⱳ潎┺ⱳ乓┺ⱳ䉍┺s
		$a_03_4 = {80 38 e9 75 0f b9 2b e1 c1 e9 c7 00 2b e1 c1 e9 c6 40 04 02 0f 20 c0 90 01 0a 82 01 00 c0 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*2) >=2
 
}