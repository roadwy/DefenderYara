
rule Worm_Win32_Autorun_NI{
	meta:
		description = "Worm:Win32/Autorun.NI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 68 65 6c 6c 5c 66 69 6e 64 5c 43 6f 6d 6d 61 6e 64 3d 52 45 43 59 43 4c 45 52 5c } //2 shell\find\Command=RECYCLER\
		$a_00_1 = {61 75 74 6f 72 75 6e 53 6f 75 72 63 65 } //1 autorunSource
		$a_00_2 = {52 45 47 2e 65 78 65 20 41 44 44 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 22 20 2f 76 20 53 68 6f 77 53 75 70 65 72 48 69 64 64 65 6e 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 20 2f 66 } //1 REG.exe ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 0 /f
		$a_01_3 = {74 73 6b 69 6c 6c 2e 65 78 65 20 55 53 42 47 75 61 72 64 } //1 tskill.exe USBGuard
		$a_01_4 = {48 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 42 69 74 44 65 66 65 6e 64 65 72 } //1 H:\Program Files\BitDefender
		$a_01_5 = {61 74 74 72 69 62 2e 65 78 65 20 2b 73 20 2b 72 20 2b 68 20 22 } //1 attrib.exe +s +r +h "
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}