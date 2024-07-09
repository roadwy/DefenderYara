
rule PWS_Win32_QQpass_EJ{
	meta:
		description = "PWS:Win32/QQpass.EJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3b 5c 24 20 7c 06 33 db 33 c0 eb 03 8b c3 43 8a 14 37 8a 04 28 32 c2 74 04 88 06 eb 02 88 16 46 49 75 dd } //1
		$a_01_1 = {44 65 62 75 67 49 6e 66 6f 4f 75 74 2e 74 78 74 } //1 DebugInfoOut.txt
		$a_01_2 = {4a 6f 61 63 68 69 6d 50 65 69 70 65 72 2e 64 61 74 } //1 JoachimPeiper.dat
		$a_01_3 = {26 51 51 4e 75 6d 62 65 72 3d 25 73 26 51 51 50 61 73 73 57 6f 72 64 3d 25 73 } //1 &QQNumber=%s&QQPassWord=%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule PWS_Win32_QQpass_EJ_2{
	meta:
		description = "PWS:Win32/QQpass.EJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {80 04 0e fe 8b c6 41 8d 78 01 8a 10 40 } //2
		$a_03_1 = {83 c0 fb 50 c6 45 ?? e9 c6 45 ?? eb } //1
		$a_00_2 = {73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 44 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 42 00 65 00 65 00 70 00 2e 00 73 00 79 00 73 00 } //1 system32\Drivers\Beep.sys
		$a_00_3 = {54 00 73 00 53 00 61 00 66 00 65 00 45 00 64 00 69 00 74 00 2e 00 64 00 61 00 74 00 } //1 TsSafeEdit.dat
		$a_00_4 = {51 00 51 00 55 00 49 00 4e 00 3a 00 25 00 73 00 20 00 50 00 57 00 44 00 48 00 41 00 53 00 48 00 3a 00 25 00 53 00 20 00 2f 00 53 00 54 00 41 00 54 00 3a 00 34 00 30 00 } //1 QQUIN:%s PWDHASH:%S /STAT:40
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}