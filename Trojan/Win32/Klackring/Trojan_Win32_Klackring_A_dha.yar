
rule Trojan_Win32_Klackring_A_dha{
	meta:
		description = "Trojan:Win32/Klackring.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {b6 b7 2d 8c c7 90 01 02 6b 5f 14 df c7 90 01 02 b1 38 a1 73 c7 90 01 02 89 c1 d2 c4 90 00 } //1
		$a_03_1 = {b6 b7 2d 8c c7 84 24 90 01 04 6b 5f 14 df c7 84 24 90 01 04 b1 38 a1 73 c7 84 24 90 01 04 89 c1 d2 c4 90 00 } //1
		$a_03_2 = {71 15 05 7c c7 90 01 02 53 21 28 09 c7 90 01 02 2c 10 35 99 c7 90 01 02 7c 4f 58 8e 90 00 } //1
		$a_03_3 = {71 15 05 7c c7 84 24 90 01 04 53 21 28 09 c7 84 24 90 01 04 2c 10 35 99 c7 84 24 90 01 04 7c 4f 58 8e 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}