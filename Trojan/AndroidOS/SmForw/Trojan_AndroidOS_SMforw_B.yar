
rule Trojan_AndroidOS_SMforw_B{
	meta:
		description = "Trojan:AndroidOS/SMforw.B,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {72 65 67 43 75 73 74 6f 6d 65 72 } //1 regCustomer
		$a_00_1 = {2f 43 6f 6e 6e 4d 61 63 68 69 6e 65 } //1 /ConnMachine
		$a_00_2 = {26 74 65 6c 63 6f 6d 70 61 6e 79 3d } //1 &telcompany=
		$a_00_3 = {73 65 6e 64 50 6f 6b 65 } //1 sendPoke
		$a_00_4 = {3d 72 65 63 65 69 76 65 73 6d 73 26 74 65 6c 6e 75 6d 3d } //1 =receivesms&telnum=
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}