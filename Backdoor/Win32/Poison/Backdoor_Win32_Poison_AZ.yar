
rule Backdoor_Win32_Poison_AZ{
	meta:
		description = "Backdoor:Win32/Poison.AZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {88 84 2e 41 1e 00 00 46 83 c4 04 81 fe 41 1e 00 00 7c e7 b0 01 eb 02 } //2
		$a_01_1 = {74 18 33 c0 8d 8e 81 3c 00 00 8a 11 88 14 30 40 49 3d 41 1e 00 00 7c f2 ff d6 } //2
		$a_01_2 = {61 6e 74 69 2e 74 78 74 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}