
rule Trojan_Win32_Zenpack_NC_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 69 73 69 78 69 72 65 72 6f 77 75 20 7a 65 6b 6f 63 6f 66 75 } //1 Hisixirerowu zekocofu
		$a_01_1 = {4d 65 67 6f 79 6f 6c 61 64 75 78 69 6e 65 76 } //1 Megoyoladuxinev
		$a_01_2 = {46 61 7a 65 67 6f 6b 6f 70 65 64 6f 67 61 } //1 Fazegokopedoga
		$a_01_3 = {43 75 73 65 7a 61 70 75 6d 75 68 75 74 } //1 Cusezapumuhut
		$a_01_4 = {4b 75 79 75 6d 6f 70 65 6b 6f 79 61 64 65 67 } //1 Kuyumopekoyadeg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}