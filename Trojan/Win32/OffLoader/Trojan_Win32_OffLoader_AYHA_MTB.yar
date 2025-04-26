
rule Trojan_Win32_OffLoader_AYHA_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.AYHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 67 72 61 6e 64 66 61 74 68 65 72 70 72 6f 64 75 63 65 2e 73 62 73 2f 72 69 6b 75 2e 70 68 70 3f } //://grandfatherproduce.sbs/riku.php?  4
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*1) >=5
 
}