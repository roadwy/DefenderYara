
rule Backdoor_Win32_Loretsys_A{
	meta:
		description = "Backdoor:Win32/Loretsys.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {53 65 54 74 49 6e 47 73 [0-0a] 72 75 73 73 69 61 6e } //1
		$a_02_1 = {41 50 54 52 41 20 20 20 20 20 20 20 25 73 [0-04] 54 72 61 6e 73 61 63 74 69 6f 6e 73 20 25 64 } //1
		$a_00_2 = {2e 44 45 46 41 55 4c 54 5c 58 46 53 5c 4c 4f 47 49 43 41 4c 5f 53 45 52 56 49 43 45 53 } //1 .DEFAULT\XFS\LOGICAL_SERVICES
		$a_01_3 = {00 72 74 6c 33 32 73 79 73 73 00 } //1
		$a_00_4 = {c1 ea 02 4a 83 fa 00 7c 16 8b 18 89 5d fc d1 45 fc 31 08 8b 4d fc 83 c0 04 4a 83 fa ff 75 ea } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}