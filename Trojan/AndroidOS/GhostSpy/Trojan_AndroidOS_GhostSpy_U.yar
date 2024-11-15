
rule Trojan_AndroidOS_GhostSpy_U{
	meta:
		description = "Trojan:AndroidOS/GhostSpy.U,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 65 76 69 63 65 20 43 6f 6e 6e 65 63 74 65 64 31 31 31 } //2 Device Connected111
		$a_01_1 = {53 65 6e 64 4f 6e 65 47 61 6c 6c 65 72 79 } //2 SendOneGallery
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}