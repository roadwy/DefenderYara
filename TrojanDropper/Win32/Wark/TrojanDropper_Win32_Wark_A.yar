
rule TrojanDropper_Win32_Wark_A{
	meta:
		description = "TrojanDropper:Win32/Wark.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 0c b8 68 00 00 00 eb 05 b8 66 00 00 00 8d 8d 90 01 01 fc ff ff 51 50 e8 90 01 02 ff ff 90 00 } //01 00 
		$a_03_1 = {76 16 8d 4c 90 01 02 e8 90 01 02 00 00 8a 14 2e 32 d0 88 14 2e 46 3b f3 72 ea 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}