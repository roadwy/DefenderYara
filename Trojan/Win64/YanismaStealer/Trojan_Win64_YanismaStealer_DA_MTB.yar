
rule Trojan_Win64_YanismaStealer_DA_MTB{
	meta:
		description = "Trojan:Win64/YanismaStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 61 63 6b 69 72 62 79 2f 73 6b 75 6c 64 2f } //1 hackirby/skuld/
		$a_01_1 = {77 61 6c 6c 65 74 73 69 6e 6a 65 63 74 69 6f 6e } //1 walletsinjection
		$a_01_2 = {75 61 63 62 79 70 61 73 73 } //1 uacbypass
		$a_01_3 = {43 68 72 6f 6d 69 75 6d 53 74 65 61 6c } //1 ChromiumSteal
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}