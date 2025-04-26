
rule Trojan_AndroidOS_Acser_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Acser.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 6d 79 63 6f 6d 70 61 6e 79 2f 6d 79 61 70 70 34 2f 41 42 43 } //1 com/mycompany/myapp4/ABC
		$a_00_1 = {62 65 67 69 6e 42 69 6e 64 53 65 72 76 69 63 65 } //1 beginBindService
		$a_00_2 = {63 72 65 61 74 65 4d 61 73 6b 56 69 65 77 } //1 createMaskView
		$a_00_3 = {73 65 74 53 65 72 76 69 63 65 49 6e 66 6f } //1 setServiceInfo
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}