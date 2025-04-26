
rule Trojan_Win32_VBInject_AVP_MSR{
	meta:
		description = "Trojan:Win32/VBInject.AVP!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {63 68 69 63 6b 61 73 61 77 73 } //chickasaws  1
		$a_80_1 = {63 61 6b 69 65 72 } //cakier  1
		$a_80_2 = {61 62 6f 6d 69 6e 61 74 65 73 } //abominates  1
		$a_80_3 = {42 72 6f 6b 65 } //Broke  1
		$a_80_4 = {4c 65 6d 75 72 } //Lemur  1
		$a_80_5 = {42 65 6c 6f 77 73 } //Belows  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}