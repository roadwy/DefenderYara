
rule Trojan_Win32_OffLoader_POFC_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.POFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 73 3a 2f 2f 6c 69 6e 65 6e 64 69 67 65 73 74 69 6f 6e 2e 69 6e 66 6f 2f 79 61 68 3f } //https://linendigestion.info/yah?  4
		$a_80_1 = {68 74 74 70 73 3a 2f 2f 64 69 72 74 72 69 76 65 72 2e 78 79 7a 2f 79 61 68 73 3f } //https://dirtriver.xyz/yahs?  4
		$a_80_2 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_3 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*4+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=6
 
}