
rule Backdoor_Win32_Farfli_AO{
	meta:
		description = "Backdoor:Win32/Farfli.AO,SIGNATURE_TYPE_PEHSTR_EXT,ffffffbe 00 ffffffaa 00 08 00 00 64 00 "
		
	strings :
		$a_01_0 = {75 73 65 72 20 67 75 65 73 74 20 72 61 74 70 70 20 26 26 20 6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 67 75 65 73 74 } //32 00  user guest ratpp && net localgroup administrators guest
		$a_01_1 = {c6 45 f1 49 c6 45 f2 33 c6 45 f3 32 c6 45 f4 2e c6 45 f5 64 c6 45 f6 6c c6 45 f7 6c c6 45 f8 00 68 } //1e 00 
		$a_01_2 = {c6 85 05 fd ff ff 72 c6 85 06 fd ff ff 64 c6 85 07 fd ff ff 70 c6 85 08 fd ff ff 77 } //0a 00 
		$a_01_3 = {43 4f 4d 4d 41 4e 44 5f 55 4e 50 41 43 4b 5f 52 41 52 20 72 65 76 65 } //0a 00  COMMAND_UNPACK_RAR reve
		$a_01_4 = {3c 48 31 3e 34 30 33 20 46 6f 72 62 69 64 64 65 6e 3c 2f 48 31 3e } //14 00  <H1>403 Forbidden</H1>
		$a_01_5 = {c6 45 f2 67 c6 45 f3 6f c6 45 f4 6c c6 45 f5 6e c6 45 f6 69 c6 45 f7 57 } //14 00 
		$a_01_6 = {c6 45 f6 72 c6 45 f7 6d c6 45 f8 53 c6 45 f9 65 c6 45 fa 72 c6 45 fb 76 c6 45 fc 69 } //14 00 
		$a_01_7 = {c6 45 f6 65 c6 45 f7 2e c6 45 f8 6e c6 45 f9 69 c6 45 fa 61 c6 45 fb 4d c6 45 fc 53 c6 45 fd 44 c6 45 fe 00 } //00 00 
		$a_00_8 = {5d 04 00 00 0f fc 02 80 5c 21 00 00 10 fc 02 80 00 00 01 00 06 00 0b 00 84 21 49 6e 66 65 78 6f 72 2e 43 00 00 01 40 05 82 42 00 04 00 80 10 00 00 bb ff 5a 8c 49 7a 46 3a 15 39 ad bf 00 0e 00 80 5d 04 00 00 10 } //fc 02 
	condition:
		any of ($a_*)
 
}