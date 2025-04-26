
rule Backdoor_Win32_Oecede_A{
	meta:
		description = "Backdoor:Win32/Oecede.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {85 c9 74 0d 33 db 8a 1a 32 d8 88 1a 42 d1 c8 e2 f5 5a 59 5b c9 c2 08 00 } //2
		$a_01_1 = {e9 da 00 00 00 81 fb 07 00 02 00 74 5b 81 fb 03 00 01 00 74 14 81 fb 07 00 03 00 0f 85 } //2
		$a_01_2 = {5c 6b 62 64 2e 73 79 73 00 00 00 5c 5c 2e 5c 6b 62 64 00 } //1
		$a_01_3 = {5c 3f 3f 5c 25 73 5c 73 76 63 68 6f 73 74 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}