
rule Backdoor_Win32_Kanafiba_A{
	meta:
		description = "Backdoor:Win32/Kanafiba.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8d 04 40 8d 1c 85 ?? ?? 45 00 83 3d ?? ?? 45 00 00 75 41 68 6d 27 00 00 8d 45 f8 } //1
		$a_01_1 = {4b 41 48 46 49 55 4e 42 41 55 53 4e 41 4b } //1 KAHFIUNBAUSNAK
		$a_03_2 = {c7 45 ec 22 c8 00 00 33 c0 55 68 ?? ?? 45 00 64 ff 30 64 89 20 b2 01 a1 } //1
		$a_01_3 = {8a 70 cc 50 c7 da 30 16 ae 33 7e fd e1 43 83 d7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}