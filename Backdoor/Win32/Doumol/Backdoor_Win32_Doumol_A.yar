
rule Backdoor_Win32_Doumol_A{
	meta:
		description = "Backdoor:Win32/Doumol.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 fe 03 74 05 80 fb 03 75 37 8b c3 e8 ?? ?? ?? ?? 83 fa ff 75 03 83 f8 ff 74 26 } //1
		$a_03_1 = {8b c7 ba 06 00 00 00 e8 ?? ?? ?? ?? 83 c3 24 4e 0f 85 65 ff ff ff 83 7d f4 00 0f 85 23 ff ff ff } //1
		$a_01_2 = {8b 95 58 ff ff ff 8b c6 8b 08 ff 51 38 43 83 fb 0a 75 94 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}