
rule Backdoor_Win32_Gaertob_A{
	meta:
		description = "Backdoor:Win32/Gaertob.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {59 6a 00 6a 0c 68 90 01 04 ff b5 90 01 02 ff ff ff 15 90 01 04 6a 01 58 85 c0 0f 84 90 01 02 00 00 6a 00 6a 63 90 00 } //1
		$a_03_1 = {ff ff 52 c6 85 90 01 01 ff ff ff 61 c6 85 90 01 01 ff ff ff 72 c6 85 90 01 01 ff ff ff 21 c6 85 90 01 01 ff ff ff 1a 90 00 } //1
		$a_03_2 = {89 45 f8 83 7d f8 03 74 06 83 7d f8 04 75 14 8d 45 fc 50 ff 15 90 01 04 83 f8 01 75 05 e8 90 01 04 8a 45 fc 2c 01 88 45 fc 0f be 45 fc 83 f8 62 75 c2 90 00 } //1
		$a_03_3 = {6e 65 70 65 6e 74 68 65 73 90 02 04 63 75 72 72 65 6e 74 75 73 65 72 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}