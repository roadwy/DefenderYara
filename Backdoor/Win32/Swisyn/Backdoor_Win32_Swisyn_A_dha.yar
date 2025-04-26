
rule Backdoor_Win32_Swisyn_A_dha{
	meta:
		description = "Backdoor:Win32/Swisyn.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b 44 24 08 8a 08 32 ca 02 ca 88 08 40 4e 75 f4 } //1
		$a_00_1 = {6a 0c 52 8d 44 24 1c 6a 0c 50 68 04 00 00 98 57 c7 44 24 2c 01 00 00 00 c7 44 24 34 e8 03 00 00 } //1
		$a_03_2 = {8b 44 24 08 3d 00 00 00 21 74 ?? 3d 00 00 00 23 75 ?? 6a 00 6a 00 6a 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}