
rule Trojan_Win32_Pincav_AML_MTB{
	meta:
		description = "Trojan:Win32/Pincav.AML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 82 60 12 40 00 83 f0 d8 88 06 46 42 83 fa 26 75 ee } //4
		$a_01_1 = {30 58 ff 40 39 d0 75 f8 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}