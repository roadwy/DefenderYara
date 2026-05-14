
rule Trojan_Win32_OffLoader_ZHG_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.ZHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 62 69 74 65 63 65 6c 65 72 79 2e 78 79 7a 2f } //://bitecelery.xyz/  3
		$a_80_1 = {3a 2f 2f 70 65 61 63 65 62 61 74 2e 63 66 64 2f } //://peacebat.cfd/  3
		$a_80_2 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  2
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*2) >=8
 
}