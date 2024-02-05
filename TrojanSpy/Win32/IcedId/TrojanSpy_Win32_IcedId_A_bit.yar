
rule TrojanSpy_Win32_IcedId_A_bit{
	meta:
		description = "TrojanSpy:Win32/IcedId.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 68 66 89 48 18 59 6a 6f 66 89 48 08 59 6a 73 5e 6a 74 66 89 48 0a 59 6a 2e 66 89 48 0e 59 6a 65 5a 6a 78 66 89 48 10 59 6a 5c 66 89 48 14 59 6a 76 66 89 08 59 6a 63 } //01 00 
		$a_01_1 = {68 94 9c 50 c5 53 57 57 0b f0 e8 } //00 00 
	condition:
		any of ($a_*)
 
}