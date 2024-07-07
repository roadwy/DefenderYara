
rule Backdoor_Win32_Delf_IW{
	meta:
		description = "Backdoor:Win32/Delf.IW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 00 00 5c 5c 2e 5c 53 4d 41 52 54 56 53 44 } //1
		$a_03_1 = {6a 00 8d 85 90 01 02 ff ff 50 68 10 02 00 00 8d 85 90 01 02 ff ff 50 6a 20 8d 85 90 01 02 ff ff 50 68 88 c0 07 00 8b 85 90 01 02 ff ff 50 e8 90 01 04 85 c0 75 90 00 } //1
		$a_03_2 = {66 ba 2e 00 66 b8 03 00 e8 90 01 04 50 6a 00 68 12 03 00 00 68 ff ff 00 00 e8 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}