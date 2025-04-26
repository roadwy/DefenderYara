
rule Trojan_Win32_Dllhijacker_PAA_MTB{
	meta:
		description = "Trojan:Win32/Dllhijacker.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 30 00 30 00 31 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 4e 00 61 00 6d 00 65 00 5c 00 43 00 6f 00 6d 00 70 00 75 00 74 00 } //1 System\ControlSet001\Control\ComputerName\Comput
		$a_01_1 = {22 43 3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 22 } //1 "C:\Windows\iexplore.exe"
		$a_01_2 = {64 65 6c 65 74 65 20 2f 66 20 2f 74 6e 20 75 70 64 61 74 65 63 66 67 53 65 74 75 70 } //1 delete /f /tn updatecfgSetup
		$a_01_3 = {74 72 6f 6c 43 3a 5c 57 69 6e 64 6f 77 73 5c 75 70 64 61 74 65 63 66 67 } //1 trolC:\Windows\updatecfg
		$a_01_4 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 73 65 74 75 70 2e 76 62 73 } //1 C:\Windows\setup.vbs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}