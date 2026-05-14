
rule Trojan_Win64_ClickFix_GVK_MTB{
	meta:
		description = "Trojan:Win64/ClickFix.GVK!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_00_0 = {66 00 69 00 6e 00 67 00 65 00 72 00 20 00 67 00 63 00 61 00 70 00 74 00 63 00 68 00 61 00 } //10 finger gcaptcha
		$a_00_1 = {7c 00 63 00 6d 00 64 00 } //10 |cmd
		$a_00_2 = {73 00 74 00 61 00 72 00 74 00 } //10 start
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=30
 
}