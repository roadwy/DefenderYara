
rule Trojan_BAT_RedLineStealer_NTW_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.NTW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 00 61 00 66 00 66 00 66 00 67 00 66 00 66 00 66 00 66 00 66 00 66 00 66 00 } //1 fafffgfffffff
		$a_01_1 = {73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 } //1 ssssssssssssssss
		$a_01_2 = {62 00 79 00 74 00 65 00 73 00 20 00 66 00 72 00 67 00 66 00 66 00 66 00 66 00 6f 00 6d 00 } //1 bytes frgffffom
		$a_01_3 = {66 00 66 00 73 00 64 00 66 00 73 00 64 00 66 00 64 00 73 00 } //1 ffsdfsdfds
		$a_01_4 = {62 00 79 00 74 00 65 00 73 00 20 00 66 00 72 00 66 00 66 00 66 00 6f 00 6d 00 } //1 bytes frfffom
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}