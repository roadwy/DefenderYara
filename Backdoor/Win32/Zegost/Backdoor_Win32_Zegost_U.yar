
rule Backdoor_Win32_Zegost_U{
	meta:
		description = "Backdoor:Win32/Zegost.U,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 86 e4 00 00 00 5f 8d 32 01 b8 01 00 00 00 5f 5e } //2
		$a_03_1 = {6a 04 50 68 02 10 00 00 68 ff ff 00 00 51 c7 44 24 90 01 01 00 80 00 00 ff d7 8b 06 8d 54 24 90 01 01 6a 04 52 68 01 10 00 00 68 ff ff 00 00 90 00 } //1
		$a_01_2 = {48 65 61 72 74 42 65 61 74 20 46 61 69 6c 20 52 65 43 6f 6e 6e 65 63 74 2e 2e 20 4f 4b 21 } //1 HeartBeat Fail ReConnect.. OK!
		$a_03_3 = {50 44 46 2d 90 10 05 00 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}