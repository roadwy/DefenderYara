
rule Trojan_Win32_OffLoader_ZVJ_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.ZVJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 69 73 6c 61 6e 64 64 69 67 65 73 74 69 6f 6e 2e 63 66 64 2f } //://islanddigestion.cfd/  3
		$a_80_1 = {3a 2f 2f 79 61 72 6e 64 61 75 67 68 74 65 72 2e 69 6e 66 6f 2f } //://yarndaughter.info/  3
		$a_80_2 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*1) >=7
 
}