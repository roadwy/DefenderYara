
rule Trojan_Win32_Fauppod_MA_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {52 66 67 68 47 76 79 67 75 62 68 } //02 00 
		$a_01_1 = {4c 6a 6e 68 44 64 63 74 66 76 67 } //02 00 
		$a_01_2 = {59 74 62 46 66 74 76 79 67 } //01 00 
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}