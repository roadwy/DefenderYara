
rule PWS_Win32_Smiwil_A{
	meta:
		description = "PWS:Win32/Smiwil.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 "
		
	strings :
		$a_01_0 = {63 73 72 73 73 2e 65 78 65 20 2f 73 68 74 6d 6c } //1 csrss.exe /shtml
		$a_01_1 = {69 65 78 70 6c 6f 72 65 2e 65 78 65 20 2f 73 68 74 6d 6c } //1 iexplore.exe /shtml
		$a_01_2 = {73 65 72 76 69 63 65 73 2e 65 78 65 20 2f 73 68 74 6d 6c } //1 services.exe /shtml
		$a_01_3 = {73 70 6f 6f 6c 73 76 2e 65 78 65 20 2f 73 68 74 6d 6c } //1 spoolsv.exe /shtml
		$a_01_4 = {25 63 6f 6d 70 75 74 65 72 6e 61 6d 65 25 2d 43 68 72 6f 6d 65 2e 68 74 6d 6c } //1 %computername%-Chrome.html
		$a_01_5 = {25 63 6f 6d 70 75 74 65 72 6e 61 6d 65 25 2d 49 45 2e 68 74 6d 6c } //1 %computername%-IE.html
		$a_01_6 = {25 63 6f 6d 70 75 74 65 72 6e 61 6d 65 25 2d 53 74 6f 72 61 67 65 2e 68 74 6d 6c } //1 %computername%-Storage.html
		$a_01_7 = {25 63 6f 6d 70 75 74 65 72 6e 61 6d 65 25 2d 46 69 72 65 66 6f 78 2e 68 74 6d 6c } //1 %computername%-Firefox.html
		$a_01_8 = {75 73 65 72 20 73 6d 69 77 69 6c 37 3e } //2 user smiwil7>
		$a_01_9 = {67 65 74 77 69 6e 64 6f 77 70 6f 73 3e 3e } //2 getwindowpos>>
		$a_02_10 = {66 74 70 20 2d 6e 20 2d 73 3a 74 65 6d 70 [0-04] 2e 72 61 72 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_02_10  & 1)*2) >=10
 
}