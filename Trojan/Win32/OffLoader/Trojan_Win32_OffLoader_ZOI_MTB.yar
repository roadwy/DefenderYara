
rule Trojan_Win32_OffLoader_ZOI_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.ZOI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 64 6f 67 73 70 65 72 73 6f 6e 2e 78 79 7a 2f 61 6d 70 73 3f } //://dogsperson.xyz/amps?  3
		$a_80_1 = {3a 2f 2f 62 65 61 72 6a 61 69 6c 2e 69 6e 66 6f 2f 61 6d 70 3f } //://bearjail.info/amp?  3
		$a_80_2 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_3 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=8
 
}