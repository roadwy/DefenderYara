
rule Backdoor_Win32_Delf_PF{
	meta:
		description = "Backdoor:Win32/Delf.PF,SIGNATURE_TYPE_PEHSTR,05 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 59 53 5f 49 4e 46 4f } //1 SYS_INFO
		$a_01_1 = {47 45 54 5f 4e 45 54 57 4f 52 4b } //1 GET_NETWORK
		$a_01_2 = {4b 45 59 4c 4f 47 } //1 KEYLOG
		$a_01_3 = {73 63 61 6e 20 7b 61 6c 6c 7d 20 2a 2e 64 6f 63 78 2c 20 2a 2e 78 6c 73 78 2c 20 2a 2e 70 64 66 2c } //1 scan {all} *.docx, *.xlsx, *.pdf,
		$a_01_4 = {46 4f 52 20 2f 46 20 22 74 6f 6b 65 6e 73 3d 32 20 64 65 6c 69 6d 73 3d 5b 5d 22 20 25 25 69 20 49 4e 20 28 27 70 69 6e 67 20 2d 61 20 2d 6e 20 31 20 2d 77 20 30 20 25 25 6e } //1 FOR /F "tokens=2 delims=[]" %%i IN ('ping -a -n 1 -w 0 %%n
		$a_01_5 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 6f 66 66 69 63 65 65 78 63 70 2e 62 69 6e } //1 C:\Users\Public\officeexcp.bin
		$a_01_6 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 64 73 65 74 2e 69 6e 69 } //1 C:\Users\Public\dset.ini
		$a_01_7 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 6b 6c 61 2e 62 69 6e } //1 C:\Users\Public\kla.bin
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=5
 
}