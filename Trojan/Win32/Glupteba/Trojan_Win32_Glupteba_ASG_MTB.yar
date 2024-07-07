
rule Trojan_Win32_Glupteba_ASG_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.ASG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c3 33 d1 33 d0 2b fa 8b cf c1 e1 04 c7 05 90 01 04 00 00 00 00 89 4c 24 10 8b 44 24 28 01 44 24 10 81 3d 90 01 04 be 01 00 00 8d 2c 3b 75 90 00 } //1
		$a_03_1 = {33 f5 31 74 24 10 8b 44 24 10 29 44 24 14 81 c3 90 01 04 ff 4c 24 1c 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}