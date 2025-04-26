
rule Trojan_Win32_Delf_FD{
	meta:
		description = "Trojan:Win32/Delf.FD,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 } //1 User-Agent: 
		$a_00_2 = {54 61 73 6b 4b 69 6c 6c 20 2f 70 69 64 } //1 TaskKill /pid
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c 57 69 6e 4e 6f 74 69 66 79 } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\WinNotify
		$a_00_4 = {54 41 70 70 49 6e 6a 65 63 74 } //1 TAppInject
		$a_00_5 = {53 65 74 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 44 61 63 6c } //1 SetSecurityDescriptorDacl
		$a_03_6 = {e8 00 00 00 00 5b [0-04] 8d 53 32 [0-04] 8d 43 2a [0-04] 52 ff 10 8b f0 [0-04] 8d 53 72 [0-04] 8d 43 2e [0-04] 52 56 ff 10 83 f8 00 74 02 [0-04] ff d0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}