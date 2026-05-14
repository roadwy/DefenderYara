
rule Trojan_Win32_OffLoader_ZQJ_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.ZQJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 63 6f 62 77 65 62 74 61 62 6c 65 2e 78 79 7a 2f } //://cobwebtable.xyz/  4
		$a_80_1 = {3a 2f 2f 62 6f 6e 65 72 61 69 6c 77 61 79 2e 69 6e 66 6f 2f } //://bonerailway.info/  4
		$a_80_2 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*4+(#a_80_2  & 1)*1) >=9
 
}