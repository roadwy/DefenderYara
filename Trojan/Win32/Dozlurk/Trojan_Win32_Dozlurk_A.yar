
rule Trojan_Win32_Dozlurk_A{
	meta:
		description = "Trojan:Win32/Dozlurk.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_03_0 = {64 6c 69 6e 6b 2e 75 63 6f 7a 2e 72 75 2f [0-03] 2e 74 78 74 } //10
		$a_01_1 = {33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1 32\svchost.exe
		$a_01_2 = {36 34 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1 64\svchost.exe
		$a_00_3 = {44 3a 5c 31 32 36 5c 44 65 6c 70 68 69 5c 48 69 41 73 6d 33 5c 63 6f 6d 70 69 6c 65 72 5c 4b 6f 6c 2e 70 61 73 } //2 D:\126\Delphi\HiAsm3\compiler\Kol.pas
		$a_01_4 = {46 6f 72 6d 00 00 00 00 41 53 4d 41 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*2+(#a_01_4  & 1)*1) >=13
 
}