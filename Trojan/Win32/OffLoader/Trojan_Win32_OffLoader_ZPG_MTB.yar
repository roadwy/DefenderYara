
rule Trojan_Win32_OffLoader_ZPG_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.ZPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 6d 65 6e 72 69 64 64 6c 65 2e 78 79 7a 2f } //://menriddle.xyz/  3
		$a_80_1 = {3a 2f 2f 6e 6f 74 65 62 61 73 65 62 61 6c 6c 2e 63 66 64 2f } //://notebaseball.cfd/  3
		$a_80_2 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  2
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*2) >=8
 
}