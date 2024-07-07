
rule Trojan_Win32_BootInstal_A_dll{
	meta:
		description = "Trojan:Win32/BootInstal.A!dll,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {62 6f 6f 74 69 6e 73 74 61 6c 6c 2e 64 6c 6c 00 62 6f 6f 74 70 72 6f } //3
		$a_01_1 = {43 6f 6e 6e 65 63 74 69 6f 6e 20 57 69 7a 61 72 64 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //1 Connection Wizard\iexplore.exe
		$a_01_2 = {43 4c 53 49 44 5c 7b 31 66 34 64 65 33 37 30 2d 64 36 32 37 2d 31 31 64 31 2d 62 61 34 66 2d 30 30 61 30 63 39 31 65 65 64 62 61 7d } //1 CLSID\{1f4de370-d627-11d1-ba4f-00a0c91eedba}
		$a_01_3 = {52 75 6e 64 6c 6c 33 32 2e 65 78 65 20 53 68 65 6c 6c 33 32 2e 64 6c 6c 2c 43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c 20 49 6e 65 74 63 70 6c 2e 63 70 6c } //1 Rundll32.exe Shell32.dll,Control_RunDLL Inetcpl.cpl
		$a_01_4 = {5c 33 36 30 73 65 5c 64 61 74 61 5c 62 6f 6f 6b 6d 61 72 6b 73 2e 64 61 74 } //1 \360se\data\bookmarks.dat
		$a_01_5 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c 43 65 76 65 6e 6e 65 74 5c } //1 \CurrentVersion\Winlogon\Notify\Cevennet\
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}