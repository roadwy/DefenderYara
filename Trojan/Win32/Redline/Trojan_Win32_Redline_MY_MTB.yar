
rule Trojan_Win32_Redline_MY_MTB{
	meta:
		description = "Trojan:Win32/Redline.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 31 90 01 17 f6 17 90 01 12 80 07 90 01 13 80 2f 90 01 13 f6 2f 47 e2 ab 90 00 } //01 00 
		$a_03_1 = {8b 7d 08 89 90 01 17 f6 17 90 01 12 80 07 90 01 13 80 2f 90 01 13 f6 2f 47 e2 ab 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}