
rule Trojan_Win32_Zusy_SXE_MTB{
	meta:
		description = "Trojan:Win32/Zusy.SXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {33 f6 90 8b 54 b4 14 8b 44 24 10 8d 4c 24 0c } //5
		$a_80_1 = {47 33 54 20 57 49 4e 44 30 57 53 20 44 33 46 33 4e 44 33 52 20 4e 33 58 54 20 54 49 4d 33 21 } //G3T WIND0WS D3F3ND3R N3XT TIM3!  3
		$a_80_2 = {74 61 73 6b 6d 67 72 2e 65 78 65 } //taskmgr.exe  1
		$a_80_3 = {6d 73 63 6f 6e 66 69 67 2e 65 78 65 } //msconfig.exe  1
		$a_80_4 = {73 68 75 74 64 6f 77 6e 2e 65 78 65 } //shutdown.exe  1
		$a_80_5 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65 } //taskkill.exe  1
	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*3+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=12
 
}