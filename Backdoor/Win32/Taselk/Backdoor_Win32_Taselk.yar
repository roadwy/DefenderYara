
rule Backdoor_Win32_Taselk{
	meta:
		description = "Backdoor:Win32/Taselk,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 e8 ?? ?? ?? ?? 8b 55 f4 8b c7 e8 ?? ?? ?? ?? ff 45 f8 4e 75 d9 } //1
		$a_01_1 = {66 b8 00 00 66 e7 70 66 89 c3 66 b8 00 00 66 e7 71 66 89 d8 66 40 66 3d 3f 00 75 e8 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}