
rule Worm_Win32_Seeav_B{
	meta:
		description = "Worm:Win32/Seeav.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {81 7d 10 00 80 00 00 0f 85 90 01 04 8b 40 0c 32 db 8d 64 24 00 a8 01 75 09 fe c3 d1 e8 80 fb 1a 7c 90 00 } //1
		$a_03_1 = {80 c3 41 0f be c3 50 68 90 01 04 8d 4c 24 5c 6a 0a 51 e8 90 01 04 83 c4 10 8d 54 24 0c 52 6a 00 8d 44 24 5c 50 68 90 01 04 6a 00 6a 00 c7 44 24 24 00 00 00 00 ff 15 90 00 } //1
		$a_01_2 = {72 75 73 62 6d 6f 6e 2e 64 6c 6c } //1 rusbmon.dll
		$a_01_3 = {6f 70 65 6e 3d 2e 5c 52 45 43 59 43 4c 45 52 5c 61 75 74 6f 72 75 6e 2e 65 78 65 } //1 open=.\RECYCLER\autorun.exe
		$a_01_4 = {4c 6f 63 61 6c 20 53 65 74 74 69 6e 67 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 55 73 62 4b 65 79 } //1 Local Settings\Microsoft\UsbKey
		$a_01_5 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 44 65 73 6b 74 6f 70 2e 69 6e 69 } //1 Microsoft\Windows\Desktop.ini
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}