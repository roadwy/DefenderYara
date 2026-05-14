
rule Trojan_Win64_ClickFix_GVL_MTB{
	meta:
		description = "Trojan:Win64/ClickFix.GVL!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,32 00 32 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 00 74 00 61 00 72 00 74 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //10 Start-Process
		$a_00_1 = {7c 00 63 00 6d 00 64 00 } //10 |cmd
		$a_00_2 = {66 00 69 00 6e 00 67 00 65 00 72 00 20 00 47 00 61 00 6c 00 6f 00 } //10 finger Galo
		$a_00_3 = {2d 00 57 00 69 00 6e 00 64 00 6f 00 77 00 53 00 74 00 79 00 6c 00 65 00 20 00 48 00 69 00 64 00 64 00 65 00 6e 00 } //10 -WindowStyle Hidden
		$a_00_4 = {56 00 65 00 72 00 69 00 66 00 79 00 } //10 Verify
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10) >=50
 
}