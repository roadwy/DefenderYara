
rule TrojanSpy_Win32_Banker_ACN{
	meta:
		description = "TrojanSpy:Win32/Banker.ACN,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {7e 5e 89 45 f0 bf 01 00 00 00 8d 45 f4 e8 90 01 1f 00 8a 54 3a ff 8b 4d fc 8a 4c 31 ff 32 d1 90 00 } //01 00 
		$a_01_1 = {6c 65 6f 63 61 6c 6f 74 65 69 72 6f } //00 00 
	condition:
		any of ($a_*)
 
}