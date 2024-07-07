
rule Backdoor_Win32_Bifrose_EY{
	meta:
		description = "Backdoor:Win32/Bifrose.EY,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {87 ca 41 f7 d1 90 02 0a 80 80 30 10 40 00 90 01 01 40 3d 00 60 00 00 72 d9 90 00 } //1
		$a_03_1 = {56 33 f6 39 75 0b 90 01 01 1b 8b 45 08 33 d2 8d 0c 06 8b c6 f7 75 14 8b 45 10 90 01 01 04 02 30 01 46 3b 75 0c 7c e5 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}