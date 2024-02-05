
rule Trojan_Win32_Fareit_SM_MTB{
	meta:
		description = "Trojan:Win32/Fareit.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {88 10 83 c1 90 01 01 73 90 09 09 00 8a 91 90 01 04 80 f2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_SM_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.SM!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 46 04 8b 16 01 d8 01 da e8 76 1e 00 00 83 c6 08 4f 75 ec } //01 00 
		$a_01_1 = {8b 55 f0 88 02 90 90 90 90 ff 45 ec ff 4d dc 0f 85 5a fe ff ff } //00 00 
	condition:
		any of ($a_*)
 
}