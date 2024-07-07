
rule Backdoor_Win32_Korplug_C{
	meta:
		description = "Backdoor:Win32/Korplug.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 12 68 28 20 00 10 8d 85 fc f7 ff ff 50 ff 15 08 20 00 10 53 56 57 6a 40 } //1
		$a_01_1 = {6b c0 64 03 c1 3d 2e 2b 33 01 0f 82 99 00 00 00 56 6a 00 } //1
		$a_01_2 = {0f b6 c0 33 c1 a3 08 30 00 10 c6 06 e9 81 35 08 30 00 10 e9 00 00 00 5e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}