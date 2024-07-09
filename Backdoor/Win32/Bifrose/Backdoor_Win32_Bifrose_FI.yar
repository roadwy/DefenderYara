
rule Backdoor_Win32_Bifrose_FI{
	meta:
		description = "Backdoor:Win32/Bifrose.FI,SIGNATURE_TYPE_PEHSTR_EXT,ffffff8d 00 ffffff8d 00 09 00 00 "
		
	strings :
		$a_02_0 = {59 0f b7 11 89 04 3a 66 83 79 02 00 74 ?? 0f b7 51 02 03 c2 83 c1 04 eb } //100
		$a_01_1 = {57 69 4e 2e 65 58 65 } //10 WiN.eXe
		$a_00_2 = {6d 73 6e 6d 73 67 72 2e 65 78 65 } //10 msnmsgr.exe
		$a_01_3 = {73 6f 66 74 77 61 52 65 5c 63 4c 61 73 73 45 73 5c 48 74 74 50 5c 53 68 65 6c 6c 5c 4f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //10 softwaRe\cLassEs\HttP\Shell\Open\command
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //10 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_5 = {62 69 6e 67 2e 6e 6f 2d 69 70 2e 62 69 7a } //1 bing.no-ip.biz
		$a_00_6 = {64 69 64 64 79 36 39 2e 6e 6f 2d 69 70 2e 6f 72 67 } //1 diddy69.no-ip.org
		$a_00_7 = {7b 44 43 36 42 32 31 33 42 2d 37 35 31 41 2d 31 38 35 43 2d 32 32 42 38 2d 37 33 38 46 38 30 39 43 42 30 35 46 7d } //1 {DC6B213B-751A-185C-22B8-738F809CB05F}
		$a_00_8 = {7b 39 42 37 31 44 38 38 43 2d 43 35 39 38 2d 34 39 33 35 2d 43 35 44 31 2d 34 33 41 41 34 44 42 39 30 38 33 36 7d } //1 {9B71D88C-C598-4935-C5D1-43AA4DB90836}
	condition:
		((#a_02_0  & 1)*100+(#a_01_1  & 1)*10+(#a_00_2  & 1)*10+(#a_01_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=141
 
}