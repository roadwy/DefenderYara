
rule Backdoor_Win32_Zegost_BX{
	meta:
		description = "Backdoor:Win32/Zegost.BX,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 69 6e 73 74 61 30 5c 64 65 66 61 75 6c 74 } //01 00  winsta0\default
		$a_00_1 = {66 44 65 6e 79 54 53 43 6f 6e 6e 65 63 74 69 6f 6e 73 } //01 00  fDenyTSConnections
		$a_00_2 = {00 5b 43 61 70 73 4c 6f 63 6b 5d 00 } //01 00  嬀慃獰潌正]
		$a_00_3 = {70 62 6b 5c 72 61 73 70 68 6f 6e 65 2e 70 62 6b } //01 00  pbk\rasphone.pbk
		$a_03_4 = {ff 2e c6 85 90 01 02 ff ff 64 c6 85 90 01 02 ff ff 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}