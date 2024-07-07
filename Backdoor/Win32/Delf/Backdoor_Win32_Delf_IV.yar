
rule Backdoor_Win32_Delf_IV{
	meta:
		description = "Backdoor:Win32/Delf.IV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //1 %SystemRoot%\System32\svchost.exe -k netsvcs
		$a_03_1 = {68 3f 00 0f 00 6a 00 6a 00 e8 90 01 04 89 45 e0 6a 00 6a 00 8d 45 d8 50 8d 45 dc 50 68 00 80 00 00 8d 85 90 01 02 ff ff 50 6a 03 6a 30 6a 00 8b 45 e0 50 e8 90 00 } //1
		$a_03_2 = {50 6a 00 6a 01 e8 90 01 04 8b d8 6a 00 53 e8 90 01 04 53 e8 90 01 04 68 88 13 00 00 e8 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}