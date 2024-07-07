
rule Trojan_Win32_Emotet_ES{
	meta:
		description = "Trojan:Win32/Emotet.ES,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 00 6d 00 65 00 63 00 68 00 61 00 6e 00 69 00 73 00 6d 00 73 00 2e 00 31 00 30 00 38 00 6f 00 74 00 68 00 65 00 72 00 71 00 77 00 6f 00 6c 00 66 00 } //1 Qmechanisms.108otherqwolf
		$a_01_1 = {61 00 64 00 64 00 72 00 65 00 73 00 73 00 2e 00 31 00 31 00 35 00 69 00 73 00 39 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 61 00 6c 00 73 00 6f 00 77 00 69 00 74 00 68 00 33 00 44 00 } //1 address.115is9Exploreralsowith3D
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}