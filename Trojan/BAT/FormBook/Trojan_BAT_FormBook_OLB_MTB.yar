
rule Trojan_BAT_FormBook_OLB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.OLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {7e 63 00 00 04 72 7d 3d 00 70 72 81 3d 00 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 0b 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 14 72 87 3d 00 70 7e 46 01 00 0a 72 8d 3d 00 70 28 } //2
		$a_01_1 = {43 00 6c 00 69 00 6e 00 69 00 63 00 } //1 Clinic
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}