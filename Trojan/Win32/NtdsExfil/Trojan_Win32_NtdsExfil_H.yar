
rule Trojan_Win32_NtdsExfil_H{
	meta:
		description = "Trojan:Win32/NtdsExfil.H,SIGNATURE_TYPE_CMDHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 00 43 00 20 00 63 00 6f 00 70 00 79 00 } //10 /C copy
		$a_00_1 = {5c 00 54 00 65 00 6d 00 70 00 5c 00 } //10 \Temp\
		$a_00_2 = {6e 00 74 00 64 00 73 00 2e 00 64 00 69 00 74 00 } //10 ntds.dit
		$a_00_3 = {76 00 6f 00 6c 00 75 00 6d 00 65 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 } //10 volumeshadowcopy
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=40
 
}