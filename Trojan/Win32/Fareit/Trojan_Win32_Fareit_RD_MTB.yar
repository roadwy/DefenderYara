
rule Trojan_Win32_Fareit_RD_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {05 f9 02 00 00 06 40 12 00 00 ff 02 04 00 00 00 ff cc 31 00 1e 14 33 e1 f8 } //01 00 
		$a_01_1 = {70 72 65 73 74 69 67 65 74 61 62 65 74 70 61 6e 6f 61 6e 6e 69 61 69 73 72 6f 75 67 68 73 } //00 00  prestigetabetpanoanniaisroughs
	condition:
		any of ($a_*)
 
}