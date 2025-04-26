
rule Backdoor_Win32_Farfli_AO{
	meta:
		description = "Backdoor:Win32/Farfli.AO,SIGNATURE_TYPE_PEHSTR_EXT,ffffffbe 00 ffffffaa 00 08 00 00 "
		
	strings :
		$a_01_0 = {75 73 65 72 20 67 75 65 73 74 20 72 61 74 70 70 20 26 26 20 6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 67 75 65 73 74 } //100 user guest ratpp && net localgroup administrators guest
		$a_01_1 = {c6 45 f1 49 c6 45 f2 33 c6 45 f3 32 c6 45 f4 2e c6 45 f5 64 c6 45 f6 6c c6 45 f7 6c c6 45 f8 00 68 } //50
		$a_01_2 = {c6 85 05 fd ff ff 72 c6 85 06 fd ff ff 64 c6 85 07 fd ff ff 70 c6 85 08 fd ff ff 77 } //30
		$a_01_3 = {43 4f 4d 4d 41 4e 44 5f 55 4e 50 41 43 4b 5f 52 41 52 20 72 65 76 65 } //10 COMMAND_UNPACK_RAR reve
		$a_01_4 = {3c 48 31 3e 34 30 33 20 46 6f 72 62 69 64 64 65 6e 3c 2f 48 31 3e } //10 <H1>403 Forbidden</H1>
		$a_01_5 = {c6 45 f2 67 c6 45 f3 6f c6 45 f4 6c c6 45 f5 6e c6 45 f6 69 c6 45 f7 57 } //20
		$a_01_6 = {c6 45 f6 72 c6 45 f7 6d c6 45 f8 53 c6 45 f9 65 c6 45 fa 72 c6 45 fb 76 c6 45 fc 69 } //20
		$a_01_7 = {c6 45 f6 65 c6 45 f7 2e c6 45 f8 6e c6 45 f9 69 c6 45 fa 61 c6 45 fb 4d c6 45 fc 53 c6 45 fd 44 c6 45 fe 00 } //20
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*50+(#a_01_2  & 1)*30+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*20+(#a_01_6  & 1)*20+(#a_01_7  & 1)*20) >=170
 
}