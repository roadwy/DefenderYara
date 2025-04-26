
rule Trojan_Win32_Padodor_GPB_MTB{
	meta:
		description = "Trojan:Win32/Padodor.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 5a 9b dd ff 7e 13 29 fe ab e5 60 00 d8 35 73 29 68 09 36 66 35 cf 7e f3 0d 7e 73 e5 7e 7e 90 8f 36 47 36 46 36 36 d7 8b 8b df 5e c3 7e 8b e5 } //5
		$a_01_1 = {4d 5a e1 3d 08 ea f4 3f 2c 38 75 f4 98 2c 3d f4 74 4d 3d 75 3f 9d 3c 75 5d 1f b3 e6 90 3f 6e 75 3d 6e aa f4 3d 4d d7 75 38 75 4c f4 1f 75 75 3f } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}