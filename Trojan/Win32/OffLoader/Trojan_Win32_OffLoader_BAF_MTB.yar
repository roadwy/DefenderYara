
rule Trojan_Win32_OffLoader_BAF_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 76 69 65 77 6e 65 72 76 65 2e 78 79 7a 2f 63 68 72 73 3f } //://viewnerve.xyz/chrs?  3
		$a_80_1 = {3a 2f 2f 74 68 65 6f 72 79 70 72 6f 70 65 72 74 79 2e 69 6e 66 6f 2f 63 68 72 3f } //://theoryproperty.info/chr?  3
		$a_80_2 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_3 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=8
 
}