
rule Backdoor_Win32_Zewit_A{
	meta:
		description = "Backdoor:Win32/Zewit.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 4f 53 54 20 2f 67 61 74 65 77 61 79 2f 72 65 70 6f 72 74 20 48 54 54 50 2f 31 2e 30 } //1 POST /gateway/report HTTP/1.0
		$a_01_1 = {62 6f 74 76 65 72 3d 25 73 26 62 75 69 6c 64 3d 25 73 } //1 botver=%s&build=%s
		$a_01_2 = {25 73 52 45 43 59 43 4c 45 52 5c 61 75 74 6f 72 75 6e 2e 65 78 65 } //1 %sRECYCLER\autorun.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}