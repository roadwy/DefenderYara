
rule TrojanSpy_Win32_Banker_ACL{
	meta:
		description = "TrojanSpy:Win32/Banker.ACL,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 31 31 2e 74 78 74 } //02 00 
		$a_01_1 = {4f 4d 48 6a 51 4d 75 6b 4f 63 35 71 } //03 00 
		$a_01_2 = {54 00 54 00 5f 00 46 00 5f 00 55 00 5f 00 43 00 } //00 00 
	condition:
		any of ($a_*)
 
}