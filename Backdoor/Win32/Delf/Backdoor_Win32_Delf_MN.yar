
rule Backdoor_Win32_Delf_MN{
	meta:
		description = "Backdoor:Win32/Delf.MN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {eb 56 b3 01 b8 50 c3 00 00 e8 ?? ?? ?? ?? 66 05 dc 05 50 e8 } //1
		$a_03_1 = {56 8d 7e 4a 8d 75 e8 a5 a5 a5 a5 5e 8d 55 e4 b8 ?? ?? ?? ?? e8 } //1
		$a_03_2 = {7c 12 43 8d 45 08 e8 ?? ?? ?? ?? 32 06 88 07 46 47 4b 75 ef 5f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}