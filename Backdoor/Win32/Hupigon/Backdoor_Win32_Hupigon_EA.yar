
rule Backdoor_Win32_Hupigon_EA{
	meta:
		description = "Backdoor:Win32/Hupigon.EA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {64 65 6c 65 74 65 6d 65 2e 62 61 74 00 } //1
		$a_03_1 = {74 0c 8b 04 24 50 55 ff d6 85 c0 0f 94 c3 57 e8 ?? ?? ?? ?? 8b c3 } //1
		$a_03_2 = {03 42 3c 8b 55 f8 89 02 8b 45 f8 8b 00 05 f8 00 00 00 89 06 8b 45 f8 8b 00 8b 50 38 8b 45 f8 8b 00 8b 40 54 e8 ?? ?? ?? ?? 8b 55 0c 03 02 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}