
rule Trojan_Win32_Fauppod_MG_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {55 62 79 63 6f 6d 69 54 72 67 79 62 } //02 00 
		$a_01_1 = {50 6e 75 62 79 45 63 66 76 67 62 68 } //02 00 
		$a_01_2 = {50 6e 75 79 62 44 74 76 79 62 } //01 00 
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 45 78 } //00 00 
	condition:
		any of ($a_*)
 
}