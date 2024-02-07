
rule Backdoor_Win32_Zuza{
	meta:
		description = "Backdoor:Win32/Zuza,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 4f 53 54 20 2f 69 6e 64 65 78 2e 61 73 70 20 48 54 54 50 2f 31 2e 31 } //01 00  POST /index.asp HTTP/1.1
		$a_01_1 = {73 65 6e 73 36 34 2e 64 6c 6c } //01 00  sens64.dll
		$a_01_2 = {6d 73 63 6d 6f 73 2e 73 79 73 } //00 00  mscmos.sys
	condition:
		any of ($a_*)
 
}