
rule Trojan_BAT_NjRAT_H_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 95 a2 3d 09 1f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 bb 00 00 00 19 00 00 00 f8 01 00 00 7b 08 } //2
		$a_01_1 = {57 69 6e 64 6f 77 73 41 70 70 6c 69 63 61 74 69 6f 6e 33 35 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 WindowsApplication35.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}