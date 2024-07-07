
rule Trojan_Win32_Comfold_A{
	meta:
		description = "Trojan:Win32/Comfold.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 68 6f 72 73 65 2e 64 61 74 } //1 comhorse.dat
		$a_01_1 = {5c 55 73 65 72 55 44 69 73 6b 49 44 2e 64 61 74 } //1 \UserUDiskID.dat
		$a_00_2 = {25 73 52 45 43 59 43 4c 45 52 5c 53 } //1 %sRECYCLER\S
		$a_03_3 = {5c 72 65 6d 6f 74 65 2e 90 03 01 01 62 64 61 74 90 00 } //1
		$a_01_4 = {5c 6d 73 72 73 73 2e 65 78 65 } //1 \msrss.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}