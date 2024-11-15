
rule Trojan_Win32_Stealc_ASGJ_MTB{
	meta:
		description = "Trojan:Win32/Stealc.ASGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f be 04 33 89 44 24 08 8b 44 24 04 31 44 24 08 8a 4c 24 08 88 0c 33 83 ff 0f 75 } //4
		$a_01_1 = {ff d7 6a 00 ff d3 81 fe 0f 4c 02 00 7f 09 46 81 fe d3 b6 0e 00 7c } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}