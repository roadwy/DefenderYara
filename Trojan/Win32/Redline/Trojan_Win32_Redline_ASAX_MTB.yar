
rule Trojan_Win32_Redline_ASAX_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff d7 80 ae 90 02 05 ff d7 80 86 90 02 05 ff d7 80 b6 90 02 05 ff d7 90 00 } //01 00 
		$a_03_1 = {ff d7 80 86 90 02 05 ff d7 80 86 90 02 05 ff d7 80 b6 90 02 05 ff d7 80 86 90 00 } //04 00 
		$a_03_2 = {ff d7 80 b6 90 02 05 ff d7 80 86 90 02 05 ff d7 80 86 90 02 05 ff d7 80 86 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}