
rule Trojan_Win32_Dacic_PGAV_MTB{
	meta:
		description = "Trojan:Win32/Dacic.PGAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {75 70 6c 6f 61 64 65 72 } //2 uploader
		$a_01_1 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 6d 73 64 6f 77 6e 6c 6f 61 64 } //2 application/x-msdownload
		$a_01_2 = {57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 61 73 77 63 6d 64 61 73 77 2e 65 78 65 } //2 Windows\System32\aswcmdasw.exe
		$a_01_3 = {2f 53 54 41 52 54 } //2 /START
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}