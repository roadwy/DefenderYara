
rule Trojan_Win32_Fareit_VZ_MTB{
	meta:
		description = "Trojan:Win32/Fareit.VZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_02_0 = {ff 34 0f 80 fb 90 01 01 58 80 f9 90 01 01 e8 90 01 04 80 fb 90 01 01 89 04 0f 3c 90 01 01 83 e9 90 01 01 80 f9 90 01 01 81 f9 90 01 04 75 90 00 } //02 00 
		$a_02_1 = {8b 04 0f 3c 90 01 01 e8 90 01 04 80 fb 90 01 01 89 04 0f 3c 90 01 01 66 41 3c 90 01 01 66 41 80 fb 90 01 01 66 41 80 fb 90 01 01 66 41 3c 90 01 01 81 f9 90 01 04 75 90 00 } //02 00 
		$a_02_2 = {31 c0 80 f9 90 01 01 0b 04 0f 3c 90 01 01 e8 90 01 04 80 fb 90 01 01 6a 90 01 01 3c 90 01 01 8f 04 0f 80 fb 90 01 01 09 04 0f 3c 90 01 01 83 e9 90 01 01 80 fb 90 01 01 81 f9 90 01 04 75 90 00 } //01 00 
		$a_02_3 = {31 f0 80 fb 90 01 01 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}