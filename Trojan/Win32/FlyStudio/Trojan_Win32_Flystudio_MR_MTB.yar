
rule Trojan_Win32_Flystudio_MR_MTB{
	meta:
		description = "Trojan:Win32/Flystudio.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 45 00 78 00 75 00 69 00 4b 00 72 00 6e 00 6c 00 6e 00 2e 00 69 00 6e 00 69 00 } //1 C:\ExuiKrnln.ini
		$a_00_1 = {6e 6f 74 65 2e 79 6f 75 64 61 6f 2e 63 6f 6d 2f 79 77 73 2f 70 75 62 6c 69 63 2f 6e 6f 74 65 } //1 note.youdao.com/yws/public/note
		$a_00_2 = {5c 43 6c 65 61 72 2e 62 61 74 } //1 \Clear.bat
		$a_00_3 = {46 59 46 69 72 65 57 61 6c 6c 2e 65 78 65 } //1 FYFireWall.exe
		$a_00_4 = {61 76 63 65 6e 74 65 72 2e 65 78 65 } //1 avcenter.exe
		$a_00_5 = {49 40 6e 70 61 70 6c 61 79 65 72 2e 64 6c 6c } //1 I@npaplayer.dll
		$a_00_6 = {49 45 58 54 32 5f 49 44 52 5f 57 41 56 45 31 } //1 IEXT2_IDR_WAVE1
		$a_00_7 = {52 65 70 6c 79 2d 54 6f 3a 20 25 73 } //1 Reply-To: %s
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=6
 
}