
rule Virus_Win32_Ranlod_gen_A{
	meta:
		description = "Virus:Win32/Ranlod.gen!A,SIGNATURE_TYPE_PEHSTR,2c 01 2c 01 09 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 72 63 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //100 SOFTWARE\Mircosoft\Windows\CurrentVersion\Run
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //100 SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
		$a_01_2 = {59 6f 75 20 61 72 65 20 69 6e 66 65 63 74 65 64 20 77 69 74 68 20 52 50 5f 56 69 72 75 73 20 21 } //100 You are infected with RP_Virus !
		$a_01_3 = {52 50 2d 56 69 72 75 73 28 4e 65 77 20 52 61 6e 64 6f 6d 20 50 61 79 6c 6f 64 65 72 20 56 69 72 75 73 29 } //100 RP-Virus(New Random Payloder Virus)
		$a_01_4 = {5c 72 70 2e 65 78 65 } //20 \rp.exe
		$a_01_5 = {52 50 5f 56 69 72 75 73 } //20 RP_Virus
		$a_01_6 = {2e 70 69 66 } //20 .pif
		$a_01_7 = {2e 73 63 72 } //20 .scr
		$a_01_8 = {2a 2e 65 78 65 } //20 *.exe
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_01_4  & 1)*20+(#a_01_5  & 1)*20+(#a_01_6  & 1)*20+(#a_01_7  & 1)*20+(#a_01_8  & 1)*20) >=300
 
}