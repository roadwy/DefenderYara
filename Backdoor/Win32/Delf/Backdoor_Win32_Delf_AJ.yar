
rule Backdoor_Win32_Delf_AJ{
	meta:
		description = "Backdoor:Win32/Delf.AJ,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 69 64 74 68 3d 30 20 68 65 69 67 68 74 3d 30 3e 3c 2f 69 66 72 61 6d 65 3e 22 } //1 width=0 height=0></iframe>"
		$a_01_1 = {2d 70 6f 72 74 20 38 30 20 2d 69 6e 73 65 72 74 20 22 3c 69 66 72 61 6d 65 20 73 72 63 3d } //2 -port 80 -insert "<iframe src=
		$a_01_2 = {2d 69 64 78 20 30 20 2d 69 70 20 } //1 -idx 0 -ip 
		$a_01_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 63 61 70 69 6e 73 74 61 6c 6c 2e 65 78 65 } //1 C:\WINDOWS\SYSTEM32\capinstall.exe
		$a_01_4 = {5c 73 65 76 69 63 65 73 2e 65 78 65 } //1 \sevices.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}