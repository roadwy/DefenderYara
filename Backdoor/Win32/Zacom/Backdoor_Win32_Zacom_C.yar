
rule Backdoor_Win32_Zacom_C{
	meta:
		description = "Backdoor:Win32/Zacom.C,SIGNATURE_TYPE_PEHSTR,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {c6 47 04 4d c6 47 05 5a c6 47 06 90 c6 47 07 00 } //5
		$a_01_1 = {2e 61 73 70 3f 48 6f 73 74 49 44 3d 00 } //1
		$a_01_2 = {53 54 54 69 70 2e 61 73 70 00 } //1
		$a_01_3 = {77 77 77 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d } //1 www.microsoft.com
		$a_01_4 = {72 65 67 20 61 64 64 20 68 6b 63 75 5c 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e 20 2f 76 } //1 reg add hkcu\software\microsoft\windows\currentversion\run /v
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}