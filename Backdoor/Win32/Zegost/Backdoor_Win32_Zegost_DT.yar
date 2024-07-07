
rule Backdoor_Win32_Zegost_DT{
	meta:
		description = "Backdoor:Win32/Zegost.DT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 11 80 ea 90 01 01 8b 45 fc 03 45 f8 88 10 8b 4d fc 03 4d f8 8a 11 80 f2 90 01 01 8b 45 fc 03 45 f8 88 10 90 00 } //1
		$a_03_1 = {83 ec 08 c6 45 90 01 01 44 c6 45 90 01 01 6c c6 45 90 01 01 6c c6 45 90 01 01 64 c6 45 90 01 01 64 c6 45 90 01 01 6f c6 45 90 01 01 73 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}