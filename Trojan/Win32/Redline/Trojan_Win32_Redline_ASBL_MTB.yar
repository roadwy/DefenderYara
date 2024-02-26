
rule Trojan_Win32_Redline_ASBL_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff d6 80 34 2f 90 01 01 ff d6 80 04 2f 90 01 01 ff d6 80 2c 2f 90 01 01 ff d6 80 04 2f 90 01 01 47 3b fb 0f 82 90 00 } //01 00 
		$a_01_1 = {77 61 72 6e 69 6e 67 20 69 73 20 74 68 65 20 69 64 65 6e 74 69 66 79 } //00 00  warning is the identify
	condition:
		any of ($a_*)
 
}