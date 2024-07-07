
rule Backdoor_Win32_Hupigon_EC_MTB{
	meta:
		description = "Backdoor:Win32/Hupigon.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {54 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //1 TResourceStream
		$a_01_1 = {65 69 6f 33 5f 64 64 38 33 5f 66 66 38 33 37 64 } //1 eio3_dd83_ff837d
		$a_01_2 = {57 69 6e 61 70 69 2e 54 6c 48 65 6c 70 33 32 } //1 Winapi.TlHelp32
		$a_01_3 = {53 79 73 74 65 6d 2e 49 6e 74 65 72 6e 61 6c 2e 45 78 63 55 74 69 6c 73 } //1 System.Internal.ExcUtils
		$a_01_4 = {64 65 75 65 6b 6c 5f 64 75 7a 6c 69 62 } //1 deuekl_duzlib
		$a_01_5 = {72 75 38 5f 66 69 65 6f 65 5f 66 66 75 33 } //1 ru8_fieoe_ffu3
		$a_01_6 = {57 69 6e 61 70 69 2e 53 48 46 6f 6c 64 65 72 } //1 Winapi.SHFolder
		$a_01_7 = {64 00 65 00 6c 00 65 00 74 00 65 00 6d 00 65 00 2e 00 62 00 61 00 74 00 } //1 deleteme.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}