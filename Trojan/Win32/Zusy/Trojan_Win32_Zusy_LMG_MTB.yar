
rule Trojan_Win32_Zusy_LMG_MTB{
	meta:
		description = "Trojan:Win32/Zusy.LMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff 55 10 8b 4f 54 8b 75 08 8b d1 c1 e9 02 8b f8 f3 a5 8b ca 83 e1 03 f3 a4 8b 4d 08 8b 51 3c 8b 75 f8 } //15
		$a_01_1 = {8b 3c 33 8b c7 83 e0 0f c1 e0 0b 8b cf 81 e1 00 04 00 00 03 c1 8b cf c1 e9 14 81 e1 00 07 00 00 8d 34 41 89 7c 24 14 0f b6 44 24 16 } //10
		$a_01_2 = {8b c6 25 00 07 00 00 c1 e0 04 8b ce 81 e1 ff 00 00 00 03 c1 8b ce d1 e9 c1 e0 10 81 e1 00 04 00 00 c1 ee 0c 03 c1 83 e6 0f 03 c6 81 e7 f0 fb 00 8f 03 c7 89 03 } //5
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=30
 
}