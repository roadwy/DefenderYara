
rule Trojan_Win32_OffLoader_AHPB_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.AHPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 63 6f 6d 70 61 72 69 73 6f 6e 72 65 67 72 65 74 2e 73 70 61 63 65 2f } //://comparisonregret.space/  4
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_2 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 62 6f 6f 74 20 6e 6f 77 3f } //Do you want to reboot now?  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=6
 
}