
rule Backdoor_Win32_Zegost_CS_bit{
	meta:
		description = "Backdoor:Win32/Zegost.CS!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8a 4d 90 01 01 8a 10 32 d1 02 d1 88 10 b8 90 01 03 00 c3 90 00 } //2
		$a_03_1 = {8b 45 10 b9 fe 00 00 00 25 ff 00 00 00 89 65 f0 99 f7 f9 c7 45 90 01 01 00 00 00 00 80 c2 90 01 01 88 55 90 00 } //2
		$a_01_2 = {8b 56 e4 50 52 ff 55 fc 8b 07 33 c9 43 83 c6 28 66 8b 48 06 3b d9 0f 8c 2b ff ff ff } //1
		$a_03_3 = {8b 0b 8b 41 28 85 c0 74 90 01 01 03 c6 85 c0 74 90 02 30 6a 00 6a 01 56 ff d0 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}