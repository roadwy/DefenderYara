
rule Trojan_Win32_XWorm_A_AMTB{
	meta:
		description = "Trojan:Win32/XWorm.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 } //ExecutionPolicy Bypass Add-MpPreference -ExclusionPath  1
		$a_80_1 = {55 72 6c 68 69 64 65 } //Urlhide  1
		$a_80_2 = {50 43 53 68 75 74 64 6f 77 6e } //PCShutdown  1
		$a_80_3 = {73 68 75 74 64 6f 77 6e 2e 65 78 65 20 2f 66 20 2f 73 20 2f 74 20 30 } //shutdown.exe /f /s /t 0  2
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*2) >=5
 
}