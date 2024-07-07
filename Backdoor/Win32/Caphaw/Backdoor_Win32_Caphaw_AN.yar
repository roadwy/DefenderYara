
rule Backdoor_Win32_Caphaw_AN{
	meta:
		description = "Backdoor:Win32/Caphaw.AN,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 04 00 00 "
		
	strings :
		$a_03_0 = {db 44 24 08 dc 05 90 01 04 e8 90 01 02 00 00 99 90 02 1f 89 90 01 01 24 04 8b 90 01 01 24 90 03 01 01 41 42 89 90 01 01 24 81 3c 24 90 01 04 72 90 00 } //1
		$a_03_1 = {8b 46 3c 8b 4c 90 01 01 54 8b d1 90 00 } //100
		$a_03_2 = {8b 4e 3c 8b 4c 90 01 01 54 8b d1 90 00 } //100
		$a_01_3 = {8b 43 3c 8b 4c 18 54 8b d1 } //100
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*100+(#a_03_2  & 1)*100+(#a_01_3  & 1)*100) >=101
 
}