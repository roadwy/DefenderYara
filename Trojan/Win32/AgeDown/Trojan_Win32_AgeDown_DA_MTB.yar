
rule Trojan_Win32_AgeDown_DA_MTB{
	meta:
		description = "Trojan:Win32/AgeDown.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {25 41 70 70 44 61 74 61 25 5c 44 6c 6c } //1 %AppData%\Dll
		$a_01_1 = {56 53 63 61 6e 50 61 74 68 3d 25 25 53 } //1 VScanPath=%%S
		$a_01_2 = {63 72 61 63 6b 69 6e 67 63 69 74 79 } //1 crackingcity
		$a_03_3 = {68 69 64 63 6f 6e 3a [0-07] 6d 61 69 6e 2e 62 61 74 } //1
		$a_03_4 = {68 69 64 63 6f 6e 3a [0-07] 56 53 2e 62 61 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}