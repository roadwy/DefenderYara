
rule Trojan_Win32_OffLoader_STD_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.STD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 61 72 67 75 6d 65 6e 74 61 62 6c 79 66 69 6c 65 2e 73 70 61 63 65 2f 61 62 73 3f } //://argumentablyfile.space/abs?  4
		$a_80_1 = {3a 2f 2f 62 61 72 65 62 65 66 75 6e 2e 73 70 61 63 65 2f 61 62 73 73 3f 62 } //://barebefun.space/abss?b  4
		$a_80_2 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_3 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*4+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=10
 
}