
rule Trojan_Win32_OffLoader_AUSB_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.AUSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 69 6e 73 65 63 74 77 6f 6d 61 6e 2e 73 70 61 63 65 2f } //://insectwoman.space/  4
		$a_80_1 = {3a 2f 2f 71 75 61 72 74 65 72 73 68 6f 65 73 2e 78 79 7a 2f } //://quartershoes.xyz/  4
		$a_80_2 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*4+(#a_80_2  & 1)*1) >=9
 
}