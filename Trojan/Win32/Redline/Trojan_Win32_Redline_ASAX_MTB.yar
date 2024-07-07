
rule Trojan_Win32_Redline_ASAX_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff d7 80 ae 90 02 05 ff d7 80 86 90 02 05 ff d7 80 b6 90 02 05 ff d7 90 00 } //1
		$a_03_1 = {ff d7 80 86 90 02 05 ff d7 80 86 90 02 05 ff d7 80 b6 90 02 05 ff d7 80 86 90 00 } //1
		$a_03_2 = {ff d7 80 b6 90 02 05 ff d7 80 86 90 02 05 ff d7 80 86 90 02 05 ff d7 80 86 90 00 } //4
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*4) >=5
 
}