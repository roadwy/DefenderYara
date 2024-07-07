
rule Backdoor_Win32_Thoper_B{
	meta:
		description = "Backdoor:Win32/Thoper.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 83 c0 01 89 45 fc 83 7d fc 04 7d 90 01 01 8b 4d fc 69 c9 90 01 04 33 d2 66 89 91 90 00 } //1
		$a_03_1 = {83 c4 08 a3 90 01 04 8b 45 18 50 8b 4d 14 51 8b 55 10 52 8b 45 0c 50 8b 4d 08 51 ff 15 90 1b 00 5d c2 14 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}