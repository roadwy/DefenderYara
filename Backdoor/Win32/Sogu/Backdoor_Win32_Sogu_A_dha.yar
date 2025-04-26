
rule Backdoor_Win32_Sogu_A_dha{
	meta:
		description = "Backdoor:Win32/Sogu.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 7d fc 5a 7e 09 b8 cc cc cc cc ff d0 } //1
		$a_03_1 = {0f b6 02 0f b6 4d ?? 0f b6 55 ?? 03 ca 0f b6 55 ?? 03 ca 0f b6 55 ?? 03 ca 33 c1 } //1
		$a_01_2 = {53 00 61 00 66 00 65 00 53 00 76 00 63 00 2e 00 65 00 78 00 65 00 } //1 SafeSvc.exe
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}