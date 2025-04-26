
rule Worm_Win32_BATRun_DA_MTB{
	meta:
		description = "Worm:Win32/BATRun.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 66 6f 6c 64 65 72 20 2f 74 72 20 64 3a 5c 66 6f 6c 64 65 72 2e 65 78 65 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f 20 31 20 2f 66 } //1 schtasks /create /tn folder /tr d:\folder.exe /sc minute /mo 1 /f
		$a_01_1 = {61 74 74 72 69 62 20 2d 68 20 2d 73 20 64 3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 attrib -h -s d:\autorun.inf
		$a_01_2 = {63 6f 70 79 20 64 3a 5c 66 6f 6c 64 65 72 2e 65 78 65 20 63 3a 5c } //1 copy d:\folder.exe c:\
		$a_01_3 = {66 6f 72 20 2f 72 20 5c 20 25 25 61 20 69 6e 20 28 66 6f 6c 64 65 72 2e 65 78 65 29 20 64 6f 20 63 6f 70 79 20 22 64 3a 5c 66 6f 6c 64 65 72 2e 65 78 65 22 20 25 25 61 } //1 for /r \ %%a in (folder.exe) do copy "d:\folder.exe" %%a
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}