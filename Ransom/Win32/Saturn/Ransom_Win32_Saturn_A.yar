
rule Ransom_Win32_Saturn_A{
	meta:
		description = "Ransom:Win32/Saturn.A,SIGNATURE_TYPE_PEHSTR,19 00 19 00 0f 00 00 "
		
	strings :
		$a_01_0 = {45 41 45 42 42 42 55 50 48 41 67 50 48 53 30 33 49 7a 34 6c 4c 43 55 36 47 78 4d 77 4e 7a 34 35 50 44 63 32 4e 53 45 35 4c 77 3d 3d } //20 EAEBBBUPHAgPHS03Iz4lLCU6GxMwNz45PDc2NSE5Lw==
		$a_01_1 = {45 41 45 42 42 42 55 50 48 41 67 50 48 53 30 33 49 7a 34 6c 4c 43 55 36 47 77 63 72 49 43 6f 69 4a 43 4e 6b 47 67 55 4e 46 54 59 78 50 43 49 2b 4e 68 67 72 50 79 41 35 4b 7a 6f 3d } //20 EAEBBBUPHAgPHS03Iz4lLCU6GwcrICoiJCNkGgUNFTYxPCI+NhgrPyA5Kzo=
		$a_01_2 = {43 77 38 56 46 42 55 50 48 41 67 50 46 41 45 48 45 67 4d 66 45 78 63 48 43 42 34 65 48 54 63 2b 4a 7a 55 70 } //20 Cw8VFBUPHAgPFAEHEgMfExcHCB4eHTc+JzUp
		$a_01_3 = {45 43 45 68 4a 44 55 76 50 43 67 50 41 79 55 67 4a 43 4d 34 62 67 3d 3d } //20 ECEhJDUvPCgPAyUgJCM4bg==
		$a_01_4 = {5c 23 44 45 43 52 59 50 54 5f 4d 59 5f 46 49 4c 45 53 23 2e 68 74 6d 6c } //10 \#DECRYPT_MY_FILES#.html
		$a_01_5 = {5c 23 44 45 43 52 59 50 54 5f 4d 59 5f 46 49 4c 45 53 23 2e 74 78 74 } //10 \#DECRYPT_MY_FILES#.txt
		$a_01_6 = {5c 23 44 45 43 52 59 50 54 5f 4d 59 5f 46 49 4c 45 53 23 2e 76 62 73 } //10 \#DECRYPT_MY_FILES#.vbs
		$a_01_7 = {73 75 33 34 70 77 68 70 63 61 66 65 69 7a 74 74 2e 6f 6e 69 6f 6e } //10 su34pwhpcafeiztt.onion
		$a_01_8 = {6e 45 63 55 30 55 58 56 68 45 75 61 31 46 67 59 } //10 nEcU0UXVhEua1FgY
		$a_01_9 = {63 6d 64 2e 65 78 65 20 2f 43 20 70 69 6e 67 20 31 2e 31 2e 31 2e 31 20 2d 6e 20 31 20 2d 77 20 33 30 30 30 20 3e 20 4e 75 6c 20 26 20 44 65 6c 20 22 25 73 22 } //10 cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del "%s"
		$a_01_10 = {2f 43 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //4 /C vssadmin.exe delete shadows /all /quiet
		$a_01_11 = {77 6d 69 63 2e 65 78 65 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //4 wmic.exe shadowcopy delete
		$a_01_12 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 } //4 bcdedit /set {default} bootstatuspolicy ignoreallfailures
		$a_01_13 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } //4 bcdedit /set {default} recoveryenabled no
		$a_01_14 = {77 62 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71 75 69 65 74 } //4 wbadmin delete catalog -quiet
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*20+(#a_01_2  & 1)*20+(#a_01_3  & 1)*20+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10+(#a_01_9  & 1)*10+(#a_01_10  & 1)*4+(#a_01_11  & 1)*4+(#a_01_12  & 1)*4+(#a_01_13  & 1)*4+(#a_01_14  & 1)*4) >=25
 
}