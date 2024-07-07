
rule Backdoor_Win32_Crugup_A{
	meta:
		description = "Backdoor:Win32/Crugup.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {55 32 39 6d 64 48 64 68 63 6d 56 63 59 33 42 77 5a 33 56 79 64 51 3d 3d } //1 U29mdHdhcmVcY3BwZ3VydQ==
		$a_01_1 = {52 30 67 31 53 79 31 48 53 30 77 34 4c 55 4e 51 55 44 51 74 52 45 55 79 4e 41 3d 3d } //1 R0g1Sy1HS0w4LUNQUDQtREUyNA==
		$a_01_2 = {78 38 36 6b 65 72 6e 65 6c 32 } //1 x86kernel2
		$a_01_3 = {7a 36 34 5f 6b 65 72 6e 65 6c } //1 z64_kernel
		$a_01_4 = {6c 69 62 2f 6d 62 2e 73 79 73 } //1 lib/mb.sys
		$a_01_5 = {6c 69 62 2f 6d 64 2e 73 79 73 } //1 lib/md.sys
		$a_03_6 = {83 ec 04 8d 45 fc ff 00 eb d1 83 3d 90 01 04 06 75 54 c7 45 fc 00 00 00 00 83 7d fc 09 7f 47 8b 45 fc c1 e0 09 05 90 01 04 89 44 24 08 8b 45 fc c1 e0 09 05 90 01 04 89 44 24 04 8b 45 fc c1 e0 09 05 90 01 04 89 04 24 e8 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*2) >=5
 
}