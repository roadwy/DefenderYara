
rule Trojan_Win32_OffLoader_POFG_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.POFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 66 65 65 6c 69 6e 67 61 63 68 69 65 76 65 72 2e 78 79 7a 2f 77 69 72 73 3f } //://feelingachiever.xyz/wirs?  3
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_2 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=5
 
}