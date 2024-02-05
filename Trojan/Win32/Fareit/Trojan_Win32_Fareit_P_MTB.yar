
rule Trojan_Win32_Fareit_P_MTB{
	meta:
		description = "Trojan:Win32/Fareit.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {66 8b 1c 0e 90 02 20 66 09 1c 0f 90 02 30 49 90 02 25 49 90 02 80 85 c9 0f 90 00 } //01 00 
		$a_00_1 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //00 00 
	condition:
		any of ($a_*)
 
}