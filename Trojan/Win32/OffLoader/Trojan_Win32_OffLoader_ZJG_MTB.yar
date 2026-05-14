
rule Trojan_Win32_OffLoader_ZJG_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.ZJG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 73 69 7a 65 67 65 65 73 65 2e 78 79 7a 2f } //://sizegeese.xyz/  3
		$a_80_1 = {3a 2f 2f 76 65 73 74 64 6f 67 2e 73 70 61 63 65 2f } //://vestdog.space/  3
		$a_80_2 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  2
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*2) >=8
 
}