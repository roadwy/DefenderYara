
rule Backdoor_Win32_Hupigon_DV{
	meta:
		description = "Backdoor:Win32/Hupigon.DV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 69 6e 66 65 63 74 20 } //01 00  -infect 
		$a_01_1 = {52 75 6e 20 69 6e 20 72 69 6e 67 30 0a 00 } //01 00 
		$a_03_2 = {8b e8 83 c4 04 85 ed 0f 84 90 01 04 81 fd 00 00 00 80 0f 82 90 01 04 81 fd ff ff ff 9f 0f 87 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}