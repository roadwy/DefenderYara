
rule Trojan_Win32_OffLoader_ANTA_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.ANTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 63 61 72 72 69 61 67 65 6c 65 74 74 65 72 2e 69 63 75 2f 6f 69 6c 2e 70 68 70 3f } //://carriageletter.icu/oil.php?  3
		$a_80_1 = {3a 2f 2f 74 72 6f 75 62 6c 65 73 69 73 74 65 72 73 2e 78 79 7a 2f 6f 69 6c 73 2e 70 68 70 3f } //://troublesisters.xyz/oils.php?  3
		$a_80_2 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_3 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=8
 
}