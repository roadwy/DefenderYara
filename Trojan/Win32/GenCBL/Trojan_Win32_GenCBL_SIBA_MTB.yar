
rule Trojan_Win32_GenCBL_SIBA_MTB{
	meta:
		description = "Trojan:Win32/GenCBL.SIBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {73 65 72 76 69 63 65 2e 65 78 65 } //service.exe  01 00 
		$a_80_1 = {25 41 50 50 44 41 54 41 25 5c 73 65 72 76 69 63 65 2e 65 78 65 } //%APPDATA%\service.exe  01 00 
		$a_80_2 = {2f 43 20 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 4d 79 41 70 70 20 2f 74 72 20 25 41 50 50 44 41 54 41 25 5c 73 65 72 76 69 63 65 2e 65 78 65 20 2f 73 74 20 30 30 3a 30 30 20 2f 64 75 20 39 39 39 39 3a 35 39 20 2f 73 63 20 64 61 69 6c 79 20 2f 72 69 20 31 20 2f 66 } ///C schtasks /create /tn MyApp /tr %APPDATA%\service.exe /st 00:00 /du 9999:59 /sc daily /ri 1 /f  01 00 
		$a_80_3 = {6c 69 62 67 63 63 5f 73 5f 64 77 32 2d 31 2e 64 6c 6c } //libgcc_s_dw2-1.dll  01 00 
		$a_80_4 = {6c 69 62 67 63 6a 2d 31 36 2e 64 6c 6c } //libgcj-16.dll  01 00 
		$a_80_5 = {5f 5f 72 65 67 69 73 74 65 72 5f 66 72 61 6d 65 5f 69 6e 66 6f } //__register_frame_info  01 00 
		$a_80_6 = {5f 5f 64 65 72 65 67 69 73 74 65 72 5f 66 72 61 6d 65 5f 69 6e 66 6f } //__deregister_frame_info  01 00 
		$a_80_7 = {63 6d 64 2e 65 78 65 } //cmd.exe  00 00 
	condition:
		any of ($a_*)
 
}