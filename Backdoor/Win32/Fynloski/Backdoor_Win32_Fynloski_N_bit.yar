
rule Backdoor_Win32_Fynloski_N_bit{
	meta:
		description = "Backdoor:Win32/Fynloski.N!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 0e 0f b6 c1 0f be 94 18 90 01 04 8b 46 08 8b 75 fc 0f be 04 30 be ff 00 00 00 33 d0 8b c1 c1 f8 08 23 c6 2b d0 8b c1 c1 f8 10 23 c6 c1 e9 18 33 d0 2b d1 90 90 8b 45 fc 8b 75 08 88 14 38 40 89 45 fc 3b 46 10 7c b8 90 00 } //3
		$a_03_1 = {68 00 80 00 00 6a 00 53 ff 55 f8 8d 87 90 01 04 89 45 08 ff 55 08 90 00 } //1
		$a_03_2 = {63 3a 5c 75 73 65 72 73 5c 67 67 67 61 73 5c 64 65 73 6b 74 6f 70 5c 73 64 73 73 64 65 65 77 5c 90 02 10 5c 73 64 64 66 73 64 5c 72 65 6c 65 61 73 65 5c 73 64 64 66 73 64 2e 70 64 62 90 00 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}