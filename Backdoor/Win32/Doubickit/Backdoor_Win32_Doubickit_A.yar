
rule Backdoor_Win32_Doubickit_A{
	meta:
		description = "Backdoor:Win32/Doubickit.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 73 73 2e 65 78 65 20 61 64 2e 64 6f 75 62 6c 63 69 6c 63 6b 2e 6e 65 74 20 39 30 30 30 00 } //1
		$a_01_1 = {5c 77 62 65 6d 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 00 } //1
		$a_03_2 = {50 8d 85 bc ca ff ff 50 e8 90 01 04 83 c4 08 c7 85 bc cb ff ff 51 00 00 00 8d 55 d4 52 6a 00 8d 8d a4 c9 ff ff 51 68 fc 14 40 00 6a 00 6a 00 e8 90 01 04 ff 75 ec e8 90 00 } //1
		$a_01_3 = {83 b8 24 36 00 00 00 74 7b 8d 55 c8 52 6a 00 6a 02 8b 4d fc ff b1 2c 36 00 00 8b 45 fc ff b0 28 36 00 00 8b 55 fc ff b2 24 36 00 00 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}