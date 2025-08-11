
rule Trojan_Win32_LummaStealer_YA_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.YA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //1 net.webclient
		$a_00_1 = {68 00 74 00 74 00 70 00 } //1 http
		$a_00_2 = {2e 00 6e 00 61 00 6d 00 65 00 } //1 .name
		$a_00_3 = {76 00 61 00 6c 00 75 00 65 00 } //1 value
		$a_00_4 = {7c 00 77 00 68 00 65 00 72 00 65 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 } //1 |where-object
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}