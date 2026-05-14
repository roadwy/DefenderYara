
rule Trojan_Win32_OffLoader_ASSB_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.ASSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 66 72 6f 67 73 6a 65 61 6e 73 2e 73 70 61 63 65 2f } //://frogsjeans.space/  4
		$a_80_1 = {3a 2f 2f 73 68 65 65 74 6d 65 6e 2e 69 6e 66 6f 2f } //://sheetmen.info/  4
		$a_80_2 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*4+(#a_80_2  & 1)*1) >=9
 
}