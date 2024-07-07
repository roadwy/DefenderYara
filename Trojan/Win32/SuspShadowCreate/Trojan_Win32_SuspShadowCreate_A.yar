
rule Trojan_Win32_SuspShadowCreate_A{
	meta:
		description = "Trojan:Win32/SuspShadowCreate.A,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 00 6d 00 69 00 63 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 } //2 wmic shadowcopy
		$a_00_1 = {77 00 6d 00 69 00 63 00 2e 00 65 00 78 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 } //2 wmic.exe shadowcopy
		$a_00_2 = {63 00 61 00 6c 00 6c 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 76 00 6f 00 6c 00 75 00 6d 00 65 00 3d 00 } //3 call create volume=
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*3) >=5
 
}