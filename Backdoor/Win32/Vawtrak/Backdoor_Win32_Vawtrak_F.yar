
rule Backdoor_Win32_Vawtrak_F{
	meta:
		description = "Backdoor:Win32/Vawtrak.F,SIGNATURE_TYPE_PEHSTR_EXT,08 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {7b 25 30 2e 34 58 25 30 2e 34 58 2d 25 30 2e 34 58 2d 25 30 2e 34 58 2d 25 30 2e 34 58 2d 25 30 2e 34 58 25 30 2e 34 58 25 30 2e 34 58 7d } //4 {%0.4X%0.4X-%0.4X-%0.4X-%0.4X-%0.4X%0.4X%0.4X}
		$a_01_1 = {8b 7c 24 14 8b f7 2b f5 8d 64 24 00 8a 1f 84 db 74 20 8b cd 8b d6 8d 9b 00 00 00 00 3a 1a 74 06 49 42 85 c9 75 f6 83 c0 07 85 c9 75 08 83 c0 02 eb 03 83 c0 07 47 46 83 6c 24 1c 01 75 ce } //2
		$a_01_2 = {61 65 69 6f 75 } //1 aeiou
		$a_03_3 = {53 3a 28 4d 4c 3b 3b 4e 57 3b 3b 3b 4c 57 29 [0-04] 44 3a 28 41 3b 4f 49 43 49 3b 47 41 3b 3b 3b 57 44 29 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}