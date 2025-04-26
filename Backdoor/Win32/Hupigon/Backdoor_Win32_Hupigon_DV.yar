
rule Backdoor_Win32_Hupigon_DV{
	meta:
		description = "Backdoor:Win32/Hupigon.DV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2d 69 6e 66 65 63 74 20 } //1 -infect 
		$a_01_1 = {52 75 6e 20 69 6e 20 72 69 6e 67 30 0a 00 } //1
		$a_03_2 = {8b e8 83 c4 04 85 ed 0f 84 ?? ?? ?? ?? 81 fd 00 00 00 80 0f 82 ?? ?? ?? ?? 81 fd ff ff ff 9f 0f 87 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}