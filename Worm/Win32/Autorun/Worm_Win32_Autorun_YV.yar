
rule Worm_Win32_Autorun_YV{
	meta:
		description = "Worm:Win32/Autorun.YV,SIGNATURE_TYPE_PEHSTR_EXT,09 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 65 6c 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 42 6f 6f 74 2e 62 61 74 } //2 del C:\Windows\Boot.bat
		$a_01_1 = {73 68 65 6c 6c 5c 41 75 74 6f 5c 43 6f 6d 6d 61 6e 64 3d 2e 2e 2e 5c } //2 shell\Auto\Command=...\
		$a_01_2 = {53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 } //1 SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile
		$a_01_3 = {49 64 54 43 50 53 65 72 76 65 72 } //1 IdTCPServer
		$a_01_4 = {45 78 70 6c 6f 72 65 72 2e 65 78 65 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 74 66 6d 6f 6e 5f 2e 65 78 65 } //3 Explorer.exe C:\Windows\System32\ctfmon_.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*3) >=6
 
}