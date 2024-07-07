
rule Backdoor_Win32_DarkVNC_A_MTB{
	meta:
		description = "Backdoor:Win32/DarkVNC.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {fe c0 83 f0 90 01 01 88 44 24 90 01 01 8b 44 24 90 01 01 04 02 83 f0 90 01 01 88 44 24 90 01 01 8b 44 24 90 01 01 04 03 83 f0 90 01 01 88 44 24 90 00 } //1
		$a_01_1 = {8a 44 14 1c 8b 4c 24 18 02 ca 0f be c0 33 c8 88 4c 14 1c 42 83 fa 0d 72 } //1
		$a_81_2 = {6d 75 75 75 75 74 65 78 } //1 muuuutex
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}