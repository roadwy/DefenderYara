
rule Backdoor_Win32_Zegost_DE_bit{
	meta:
		description = "Backdoor:Win32/Zegost.DE!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 5c c6 85 90 01 04 52 c6 85 90 01 04 75 c6 85 90 01 04 25 c6 85 90 01 04 64 c6 85 90 01 04 2e c6 85 90 01 04 45 90 00 } //01 00 
		$a_03_1 = {ff 50 c6 85 90 01 04 6c c6 85 90 01 04 75 c6 85 90 01 04 67 c6 85 90 01 04 69 c6 85 90 01 04 6e c6 85 90 01 04 33 c6 85 90 01 04 32 c6 85 90 01 04 2e c6 85 90 01 04 64 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}