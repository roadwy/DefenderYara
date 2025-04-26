
rule Trojan_Win32_Depriz_F_dha{
	meta:
		description = "Trojan:Win32/Depriz.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 68 75 74 64 6f 77 6e 20 2d 72 20 2d 66 20 2d 74 20 32 } //1 shutdown -r -f -t 2
		$a_03_1 = {5c 00 69 00 6e 00 66 00 5c 00 [0-10] 2e 00 70 00 6e 00 66 00 } //1
		$a_01_2 = {74 79 70 65 3d 20 6b 65 72 6e 65 6c 20 73 74 61 72 74 3d 20 64 65 6d 61 6e 64 20 62 69 6e 70 61 74 68 3d 20 53 79 73 74 65 6d 33 32 5c 44 72 69 76 65 72 73 5c } //1 type= kernel start= demand binpath= System32\Drivers\
		$a_01_3 = {6e 00 74 00 65 00 72 00 74 00 6d 00 67 00 72 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //1 ntertmgr32.exe
		$a_01_4 = {6e 00 74 00 65 00 72 00 74 00 6d 00 67 00 72 00 36 00 34 00 2e 00 65 00 78 00 65 00 } //1 ntertmgr64.exe
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}