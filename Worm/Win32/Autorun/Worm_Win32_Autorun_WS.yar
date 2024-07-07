
rule Worm_Win32_Autorun_WS{
	meta:
		description = "Worm:Win32/Autorun.WS,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b 45 08 89 45 e4 68 90 01 04 8b 4d e4 51 e8 90 01 04 83 c4 08 8b f4 6a 00 6a 00 6a 02 6a 00 6a 00 68 00 00 00 40 8b 55 e4 52 ff 15 90 00 } //1
		$a_00_1 = {63 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 5c 6d 73 64 75 6d 70 72 65 70 2e 65 78 65 20 25 31 } //1 c:\Windows\System\msdumprep.exe %1
		$a_00_2 = {5b 00 41 00 75 00 74 00 6f 00 52 00 75 00 6e 00 5d 00 } //1 [AutoRun]
		$a_00_3 = {6f 00 70 00 65 00 6e 00 3d 00 6d 00 73 00 64 00 75 00 6d 00 70 00 72 00 65 00 70 00 2e 00 65 00 78 00 65 00 } //1 open=msdumprep.exe
		$a_00_4 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 5c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 6d 00 73 00 64 00 75 00 6d 00 70 00 72 00 65 00 70 00 2e 00 65 00 78 00 65 00 } //1 shell\explore\Command=msdumprep.exe
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}