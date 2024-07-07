
rule Trojan_Win32_Spycos_I{
	meta:
		description = "Trojan:Win32/Spycos.I,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 74 72 6f 6c 50 61 6e 65 6c 43 70 6c 2e 63 70 6c } //4 ControlPanelCpl.cpl
		$a_01_1 = {55 50 44 20 31 30 20 44 49 53 43 41 52 44 41 42 4c 45 20 22 68 74 6d 6c 67 72 64 2e 65 78 65 22 } //4 UPD 10 DISCARDABLE "htmlgrd.exe"
		$a_01_2 = {5b 20 49 4e 46 45 43 54 20 56 49 41 20 54 58 54 } //1 [ INFECT VIA TXT
		$a_01_3 = {50 6c 75 67 69 6e 20 52 45 44 2e 2e 2e 2e 2e 2e } //1 Plugin RED......
		$a_01_4 = {50 6c 75 67 69 6e 20 47 42 2e 2e 2e 2e 2e 2e 2e } //1 Plugin GB.......
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=10
 
}