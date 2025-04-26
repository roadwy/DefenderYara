
rule Trojan_Win32_Nodersok_B{
	meta:
		description = "Trojan:Win32/Nodersok.B,SIGNATURE_TYPE_CMDHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //10 powershell.exe
		$a_00_1 = {2d 00 65 00 6e 00 63 00 } //10 -enc
		$a_00_2 = {6c 00 67 00 61 00 6f 00 61 00 63 00 69 00 61 00 65 00 77 00 61 00 77 00 61 00 68 00 30 00 61 00 65 00 77 00 61 00 78 00 61 00 68 00 30 00 61 00 69 00 67 00 61 00 67 00 61 00 63 00 30 00 61 00 7a 00 67 00 61 00 6e 00 61 00 67 00 6b 00 61 00 6a 00 77 00 61 00 73 00 61 00 63 00 63 00 61 00 7a 00 71 00 62 00 34 00 61 00 63 00 63 00 61 00 6b 00 71 00 61 00 67 00 61 00 63 00 71 00 61 00 } //10 lgaoaciaewawah0aewaxah0aigagac0azganagkajwasaccazqb4accakqagacqa
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=30
 
}