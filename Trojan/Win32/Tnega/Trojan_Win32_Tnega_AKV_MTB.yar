
rule Trojan_Win32_Tnega_AKV_MTB{
	meta:
		description = "Trojan:Win32/Tnega.AKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 6a 73 64 } //https://cdn.jsd  1
		$a_80_1 = {67 68 2f 69 38 37 39 32 34 68 67 48 64 } //gh/i87924hgHd  1
		$a_80_2 = {79 2f 62 62 6f 78 66 75 3c 27 2c 20 27 74 68 61 74 33 2e 65 } //y/bboxfu<', 'that3.e  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}