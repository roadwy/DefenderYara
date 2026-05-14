
rule Trojan_Win32_ClickFix_ABE_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.ABE!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 00 75 00 72 00 6c 00 20 00 2d 00 6b 00 66 00 53 00 4c 00 73 00 } //1 curl -kfSLs
		$a_00_1 = {2d 00 2d 00 63 00 6f 00 6d 00 70 00 72 00 65 00 73 00 73 00 65 00 64 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 } //1 --compressed https://
		$a_00_2 = {7c 00 20 00 7a 00 73 00 68 00 } //1 | zsh
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}