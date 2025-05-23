
rule Virus_Win32_Fakefire_B{
	meta:
		description = "Virus:Win32/Fakefire.B,SIGNATURE_TYPE_PEHSTR_EXT,25 00 25 00 0c 00 00 "
		
	strings :
		$a_02_0 = {c7 45 f0 00 00 00 00 c7 45 f4 00 00 00 00 8b 45 08 8b 08 8b 55 08 52 ff 51 04 c7 45 fc 01 00 00 00 c7 45 fc 02 00 00 00 6a ff ff 15 ?? ?? 40 00 c7 45 fc 03 00 00 00 6a 00 68 ?? ?? 40 00 8d 45 88 50 ff 15 ?? ?? 40 00 8d 4d 88 51 8d 55 c0 52 ff 15 ?? ?? 40 00 c7 45 fc 04 00 00 00 c7 85 60 ff ff ff 01 00 00 00 c7 85 58 ff ff ff 02 00 00 00 c7 85 50 ff ff ff 14 00 00 00 c7 85 48 ff ff ff 02 00 00 00 c7 85 40 ff ff ff 01 00 00 00 c7 85 38 ff ff ff 02 00 00 00 8d 85 58 ff ff ff 50 8d 8d 48 ff ff ff 51 8d 95 38 ff ff ff 52 8d 85 c8 fe ff ff 50 8d 8d d8 fe ff ff 51 8d 55 b0 52 } //10
		$a_00_1 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //10 MSVBVM60.DLL
		$a_00_2 = {4d 00 73 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 } //2 Msfirewall
		$a_00_3 = {43 00 3a 00 5c 00 56 00 42 00 56 00 69 00 72 00 75 00 73 00 5c 00 } //2 C:\VBVirus\
		$a_00_4 = {2e 00 70 00 74 00 74 00 } //2 .ptt
		$a_00_5 = {2a 00 2e 00 65 00 78 00 65 00 } //2 *.exe
		$a_00_6 = {5c 00 53 00 65 00 74 00 31 00 2e 00 49 00 63 00 6f 00 } //2 \Set1.Ico
		$a_00_7 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 56 00 69 00 73 00 75 00 61 00 6c 00 20 00 53 00 74 00 75 00 64 00 69 00 6f 00 5c 00 56 00 42 00 39 00 38 00 5c 00 70 00 6a 00 74 00 } //2 C:\Program Files\Microsoft Visual Studio\VB98\pjt
		$a_00_8 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 2f 00 73 00 20 00 73 00 63 00 72 00 72 00 75 00 6e 00 2e 00 64 00 6c 00 6c 00 } //2 regsvr32.exe /s scrrun.dll
		$a_00_9 = {4f 00 75 00 74 00 6c 00 6f 00 6f 00 6b 00 2e 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 } //2 Outlook.Application
		$a_00_10 = {66 6c 65 49 6e 66 65 63 74 } //1 fleInfect
		$a_00_11 = {66 6c 65 46 75 63 6b } //1 fleFuck
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2+(#a_00_7  & 1)*2+(#a_00_8  & 1)*2+(#a_00_9  & 1)*2+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1) >=37
 
}