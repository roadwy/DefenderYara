
rule Worm_Win32_Autorun_CM{
	meta:
		description = "Worm:Win32/Autorun.CM,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 05 00 00 "
		
	strings :
		$a_01_0 = {eb 10 66 62 3a 43 2b 2b 48 4f 4f 4b 90 e9 } //20
		$a_00_1 = {67 65 6f 63 69 74 69 65 73 2e 63 6f 6d 2f 67 61 6d 65 73 6c 69 6e 6b 2f } //10 geocities.com/gameslink/
		$a_00_2 = {5c 53 79 73 74 65 6d 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //10 \System\svchost.exe
		$a_00_3 = {00 75 70 64 61 74 65 2e 65 78 65 00 61 75 74 6f 72 75 6e 2e 69 6e 66 00 } //10
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*20+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1) >=51
 
}