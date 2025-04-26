
rule Ransom_Win32_Rakhni_S{
	meta:
		description = "Ransom:Win32/Rakhni.S,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 49 00 6e 00 74 00 65 00 6c 00 5c 00 70 00 72 00 69 00 76 00 61 00 74 00 2e 00 65 00 78 00 65 00 } //1 C:\Intel\privat.exe
		$a_01_1 = {43 00 3a 00 5c 00 49 00 6e 00 74 00 65 00 6c 00 5c 00 62 00 6d 00 63 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //1 C:\Intel\bmcon.exe
		$a_01_2 = {2f 76 20 70 72 69 76 61 74 65 20 2f 74 20 72 65 67 5f 73 7a 20 2f 64 20 22 25 53 59 53 54 45 4d 44 52 49 56 45 25 5c 49 6e 74 65 6c 5c 70 72 69 76 61 74 2e 65 78 65 22 20 2f 66 } //1 /v private /t reg_sz /d "%SYSTEMDRIVE%\Intel\privat.exe" /f
		$a_01_3 = {73 65 74 20 70 61 73 73 3d 65 70 73 69 6c 6f 6e 65 72 69 64 61 6e 61 } //1 set pass=epsiloneridana
		$a_01_4 = {25 53 59 53 54 45 4d 44 52 49 56 45 25 5c 49 6e 74 65 6c 5c 73 65 6e 64 65 72 2e 65 78 65 20 2d 74 6f 20 } //1 %SYSTEMDRIVE%\Intel\sender.exe -to 
		$a_01_5 = {64 65 6c 20 2f 71 20 25 53 59 53 54 45 4d 44 52 49 56 45 25 5c 49 6e 74 65 6c 5c 65 6e 61 62 6c 65 2e 63 6d 64 } //1 del /q %SYSTEMDRIVE%\Intel\enable.cmd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}