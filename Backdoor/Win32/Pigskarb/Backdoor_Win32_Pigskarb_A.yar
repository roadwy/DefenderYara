
rule Backdoor_Win32_Pigskarb_A{
	meta:
		description = "Backdoor:Win32/Pigskarb.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8d 47 01 89 46 04 8d 47 05 89 46 08 83 c6 0c 8d 45 ?? c7 45 f4 05 00 00 00 e9 ?? ?? ?? ?? 8a d0 80 e2 fd 80 fa e9 75 } //1
		$a_03_1 = {6a 39 33 d2 59 89 45 f8 f7 f1 83 fb 04 0f 84 ?? ?? ?? ?? 83 fb 07 0f 8e ?? ?? ?? ?? 83 fb 09 7e ?? 83 fb 0a 75 ?? 6b d2 11 } //1
		$a_03_2 = {81 3b c8 00 00 00 75 ?? 0f be 06 83 f8 7f 77 ?? 83 65 fc 00 8d 45 fc 50 56 e8 } //1
		$a_03_3 = {8b 0e 83 c4 10 85 c9 74 0f 83 f9 0f 74 0a 83 f9 17 74 05 83 f9 12 75 ?? e8 ?? ?? ?? ?? 85 c0 75 01 47 e8 ?? ?? ?? ?? 33 d2 b9 e8 03 00 00 f7 f1 83 c2 64 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}