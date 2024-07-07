
rule Trojan_Win32_Delf_QB{
	meta:
		description = "Trojan:Win32/Delf.QB,SIGNATURE_TYPE_PEHSTR,1e 00 19 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6d 6f 73 77 61 72 2e 63 61 64 } //10 c:\windows\system32\cmoswar.cad
		$a_01_1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 77 69 6e 64 6f 77 73 78 70 2e 69 6e 69 } //10 c:\windows\system32\windowsxp.ini
		$a_01_2 = {5b 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5d } //5 [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
		$a_01_3 = {7b 45 43 43 42 46 30 30 33 2d 33 44 34 46 2d 34 39 42 39 2d 38 34 44 44 2d 33 38 32 33 34 46 38 44 30 37 41 42 7d } //5 {ECCBF003-3D4F-49B9-84DD-38234F8D07AB}
		$a_01_4 = {61 72 75 6e 2e 72 65 67 } //5 arun.reg
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5) >=25
 
}