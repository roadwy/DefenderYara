
rule Backdoor_Win32_Zegost_DA_bit{
	meta:
		description = "Backdoor:Win32/Zegost.DA!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 dc 44 6c 6c 46 c7 45 e0 75 55 70 67 c7 45 e4 72 61 64 72 66 c7 45 e8 73 00 } //01 00 
		$a_01_1 = {c7 45 ec 44 68 6c 56 50 56 c7 45 f0 69 70 56 65 c7 45 f4 72 73 66 73 } //00 00 
	condition:
		any of ($a_*)
 
}