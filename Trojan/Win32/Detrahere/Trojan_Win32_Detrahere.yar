
rule Trojan_Win32_Detrahere{
	meta:
		description = "Trojan:Win32/Detrahere,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {7b 00 41 00 c7 84 24 ?? ?? ?? ?? 42 00 45 00 c7 84 24 ?? ?? ?? ?? 34 00 37 00 c7 84 24 ?? ?? ?? ?? 42 00 37 00 c7 84 24 ?? ?? ?? ?? 32 00 2d 00 c7 84 24 ?? ?? ?? ?? 30 00 43 00 c7 84 24 ?? ?? ?? ?? 32 00 46 00 c7 84 24 ?? ?? ?? ?? 2d 00 34 00 c7 84 24 ?? ?? ?? ?? 32 00 31 00 c7 84 24 ?? ?? ?? ?? 46 00 2d 00 } //1
		$a_01_1 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 53 00 65 00 74 00 75 00 70 00 4d 00 75 00 74 00 65 00 78 00 5f 00 } //1 Global\SetupMutex_
		$a_01_2 = {43 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5f 00 4d 00 65 00 73 00 73 00 61 00 67 00 65 00 50 00 75 00 6d 00 70 00 57 00 69 00 6e 00 64 00 6f 00 77 00 } //1 CChrome_MessagePumpWindow
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Detrahere_2{
	meta:
		description = "Trojan:Win32/Detrahere,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 67 70 74 39 2e 63 6f 6d 2f 61 70 69 2f 63 70 78 3f 71 3d } //1 http://gpt9.com/api/cpx?q=
		$a_01_1 = {47 6c 6f 62 61 6c 5c 73 70 6c 73 72 76 } //1 Global\splsrv
		$a_01_2 = {5c 53 6d 61 72 74 53 65 72 76 69 63 65 5c 52 65 6c 65 61 73 65 5c 73 70 6c 73 72 76 2e 70 64 62 } //1 \SmartService\Release\splsrv.pdb
		$a_01_3 = {48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 } //1 HARDWARE\DESCRIPTION\System\CentralProcessor\0
		$a_01_4 = {6d 00 69 00 6e 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 5c 00 63 00 72 00 74 00 73 00 5c 00 75 00 63 00 72 00 74 00 5c 00 69 00 6e 00 63 00 5c 00 63 00 6f 00 72 00 65 00 63 00 72 00 74 00 5f 00 69 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 5f 00 73 00 74 00 72 00 74 00 6f 00 78 00 2e 00 68 00 } //1 minkernel\crts\ucrt\inc\corecrt_internal_strtox.h
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}