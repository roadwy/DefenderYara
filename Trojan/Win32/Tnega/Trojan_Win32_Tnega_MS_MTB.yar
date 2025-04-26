
rule Trojan_Win32_Tnega_MS_MTB{
	meta:
		description = "Trojan:Win32/Tnega.MS!MTB,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {73 71 6c 69 74 65 33 2e 64 6c 6c } //1 sqlite3.dll
		$a_01_2 = {5c 00 49 00 6e 00 50 00 72 00 6f 00 63 00 53 00 65 00 72 00 76 00 65 00 72 00 33 00 32 00 } //1 \InProcServer32
		$a_01_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 41 76 61 73 74 20 53 6f 66 74 77 61 72 65 5c 41 76 61 73 74 5c 61 73 77 52 65 73 70 2e 64 61 74 } //1 C:\ProgramData\Avast Software\Avast\aswResp.dat
		$a_01_4 = {5f 61 63 6d 64 6c 6e } //1 _acmdln
		$a_01_5 = {5f 58 63 70 74 46 69 6c 74 65 72 } //1 _XcptFilter
		$a_01_6 = {5f 5f 73 65 74 75 73 65 72 6d 61 74 68 65 72 72 } //1 __setusermatherr
		$a_01_7 = {5f 5f 70 5f 5f 63 6f 6d 6d 6f 64 65 } //1 __p__commode
		$a_01_8 = {43 73 72 46 72 65 65 43 61 70 74 75 72 65 42 75 66 66 65 72 } //1 CsrFreeCaptureBuffer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}