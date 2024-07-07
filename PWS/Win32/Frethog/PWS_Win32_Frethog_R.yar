
rule PWS_Win32_Frethog_R{
	meta:
		description = "PWS:Win32/Frethog.R,SIGNATURE_TYPE_PEHSTR,1b 00 1b 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //20 CreateToolhelp32Snapshot
		$a_01_1 = {52 61 76 4d 6f 6e 2e 65 78 65 } //2 RavMon.exe
		$a_01_2 = {71 71 64 6f 6f 72 25 64 2e 64 6c 6c } //2 qqdoor%d.dll
		$a_01_3 = {50 72 6f 64 75 63 74 5f 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //1 Product_Notification
		$a_01_4 = {41 6c 65 72 74 44 69 61 6c 6f 67 } //1 AlertDialog
		$a_01_5 = {46 69 6c 4d 73 67 2e 65 78 65 } //1 FilMsg.exe
		$a_01_6 = {54 77 69 73 74 65 72 2e 65 78 65 } //1 Twister.exe
		$a_01_7 = {44 36 34 41 43 32 45 34 2d 34 30 44 44 2d 39 30 44 39 2d 39 35 42 31 2d 30 43 36 30 46 37 43 41 36 34 42 46 } //1 D64AC2E4-40DD-90D9-95B1-0C60F7CA64BF
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=27
 
}