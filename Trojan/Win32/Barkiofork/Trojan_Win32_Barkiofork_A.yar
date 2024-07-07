
rule Trojan_Win32_Barkiofork_A{
	meta:
		description = "Trojan:Win32/Barkiofork.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {70 3d 31 00 2f 73 2f 61 73 70 3f } //1
		$a_01_1 = {61 76 70 2e 65 78 65 00 5c 63 6d 64 2e 65 78 65 } //1
		$a_01_2 = {25 75 20 4d 42 28 25 73 29 2f 25 75 20 4d 42 28 25 73 29 0a } //1
		$a_01_3 = {25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 54 65 6d 70 5c 7e 49 53 55 4e 33 32 2e 45 58 45 } //1 %USERPROFILE%\Temp\~ISUN32.EXE
		$a_01_4 = {75 11 b9 bb 01 00 00 eb 0a 8b 4d 0c 3b cf 75 03 6a 50 } //1
		$a_03_5 = {77 1b 8b c1 0f af c1 0f af c1 25 ff 00 00 00 3d 80 00 00 00 76 07 30 90 01 06 41 90 00 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*3) >=3
 
}