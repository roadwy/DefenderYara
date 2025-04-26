
rule Backdoor_Win32_Delf_BA_MTB{
	meta:
		description = "Backdoor:Win32/Delf.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b d3 8b da d1 eb 33 98 34 06 00 00 83 e2 01 33 1c 95 b0 90 40 00 89 18 83 c0 04 49 75 } //2
		$a_01_1 = {88 c3 32 1e c1 e8 08 46 33 04 9d 94 b6 40 00 e2 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}