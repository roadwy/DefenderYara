
rule Trojan_Win32_OffLoader_PGON_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.PGON!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_02_0 = {67 00 65 00 74 00 00 00 31 00 30 00 32 00 33 00 [0-ff] 2e 00 65 00 78 00 65 00 [0-1f] 2e 00 65 00 78 00 65 00 } //3
		$a_02_1 = {67 65 74 00 00 31 30 32 33 [0-ff] 2e 65 78 65 [0-1f] 2e 65 78 65 } //3
		$a_80_2 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  2
	condition:
		((#a_02_0  & 1)*3+(#a_02_1  & 1)*3+(#a_80_2  & 1)*2) >=5
 
}