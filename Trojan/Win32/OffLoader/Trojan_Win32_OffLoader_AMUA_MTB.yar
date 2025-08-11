
rule Trojan_Win32_OffLoader_AMUA_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.AMUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 74 65 65 74 68 65 6c 62 6f 77 2e 69 63 75 2f 74 72 69 2e 70 68 70 3f } //://teethelbow.icu/tri.php?  4
		$a_80_1 = {3a 2f 2f 6d 69 6e 69 73 74 65 72 6b 69 73 73 2e 78 79 7a 2f 74 72 69 73 2e 70 68 70 3f } //://ministerkiss.xyz/tris.php?  4
		$a_80_2 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_3 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*4+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=10
 
}