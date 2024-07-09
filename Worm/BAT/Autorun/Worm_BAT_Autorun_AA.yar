
rule Worm_BAT_Autorun_AA{
	meta:
		description = "Worm:BAT/Autorun.AA,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_02_0 = {63 6f 70 79 20 2f 79 20 25 30 20 ?? 3a 5c [0-10] 2e 65 78 65 } //1
		$a_02_1 = {65 63 68 6f 20 5b 41 75 74 6f 52 75 6e 5d 20 3e 20 ?? 3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1
		$a_02_2 = {65 63 68 6f 20 73 68 65 6c 6c 65 78 65 63 75 74 65 3d [0-32] 2e 65 78 65 20 3e 3e 20 ?? 3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1
		$a_00_3 = {69 66 20 65 78 69 73 74 20 25 7e 64 70 30 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 20 73 74 61 72 74 20 25 7e 64 70 30 } //1 if exist %~dp0\autorun.inf start %~dp0
		$a_01_4 = {5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74 22 20 2f 76 20 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 66 74 70 2e 65 78 65 } //1 \SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List" /v %windir%\system32\ftp.exe
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}