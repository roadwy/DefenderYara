
rule Worm_Win32_Kuwawa_A{
	meta:
		description = "Worm:Win32/Kuwawa.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {5b 41 75 74 6f 52 75 6e [0-06] 61 [0-06] 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1
		$a_03_1 = {25 73 5c 57 69 6e 64 6f 77 73 55 70 64 61 74 65 2e 65 78 65 [0-06] 6f 70 65 6e [0-06] 65 78 70 6c 6f 72 65 } //1
		$a_01_2 = {73 68 65 6c 6c 5c 4f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 3d 53 79 73 74 65 6d 5f 56 6f 6c 75 6d 65 5f 49 6e 66 6f 72 6d 61 74 69 6f 6e 5c 5f 72 65 73 74 6f 72 65 7b 32 36 38 36 34 43 31 37 2d 31 38 44 44 2d 34 35 36 31 2d 38 34 31 30 7d 5c 64 72 69 76 65 72 2e 65 78 65 20 2d 6f } //1 shell\Open\command=System_Volume_Information\_restore{26864C17-18DD-4561-8410}\driver.exe -o
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}