
rule Trojan_Win32_ClickFix_HW_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.HW!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,3c 00 3c 00 02 00 00 "
		
	strings :
		$a_00_0 = {2f 00 2f 00 3a 00 73 00 70 00 74 00 74 00 68 00 } //10 //:sptth
		$a_02_1 = {69 00 65 00 78 00 28 00 69 00 77 00 72 00 20 00 28 00 5b 00 73 00 74 00 72 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 6a 00 6f 00 69 00 6e 00 28 00 27 00 27 00 2c 00 28 00 24 00 [0-08] 5b 00 2d 00 31 00 2e 00 2e 00 2d 00 24 00 90 1b 00 2e 00 6c 00 65 00 6e 00 67 00 74 00 68 00 5d 00 29 00 } //50
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*50) >=60
 
}