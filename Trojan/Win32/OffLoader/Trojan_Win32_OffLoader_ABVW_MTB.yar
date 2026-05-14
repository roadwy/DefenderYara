
rule Trojan_Win32_OffLoader_ABVW_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.ABVW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 63 68 61 6c 6b 69 63 65 2e 78 79 7a 2f } //://chalkice.xyz/  2
		$a_80_1 = {3a 2f 2f 70 6f 74 61 74 6f 6b 65 79 2e 78 79 7a 2f } //://potatokey.xyz/  2
		$a_80_2 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=6
 
}