
rule Trojan_Win32_Amadey_EM_MTB{
	meta:
		description = "Trojan:Win32/Amadey.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0f 32 cb 66 81 ea 59 53 0f bc d3 d2 d6 80 c1 ef d0 c9 66 81 ca 46 52 66 85 c8 80 c1 16 d2 da 66 0f ca 80 f1 b8 32 d9 89 04 0c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Amadey_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {49 53 4e 6d 66 56 3d 3d } //1 ISNmfV==
		$a_81_1 = {56 33 42 66 31 48 57 6f 62 79 74 3d } //1 V3Bf1HWobyt=
		$a_81_2 = {4a 6a 73 72 50 6c 3d 3d } //1 JjsrPl==
		$a_81_3 = {52 33 4a 62 65 73 49 35 63 73 3d 3d } //1 R3JbesI5cs==
		$a_81_4 = {25 75 73 65 72 61 70 70 64 61 74 61 25 5c 52 65 73 74 61 72 74 41 70 70 2e 65 78 65 } //1 %userappdata%\RestartApp.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}