
rule Trojan_Win32_Farfli_CCGF_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CCGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff d3 0f 28 05 90 01 04 6a 18 0f 11 45 c8 c7 45 90 01 01 63 2f 2f 44 c7 45 90 01 01 6f 63 75 6d c7 45 90 01 01 65 6e 74 73 66 c7 45 90 01 01 2f 2f c6 45 e6 00 ff d3 90 00 } //01 00 
		$a_01_1 = {68 f8 f5 40 00 68 70 f6 40 00 68 80 f6 40 00 6a 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}