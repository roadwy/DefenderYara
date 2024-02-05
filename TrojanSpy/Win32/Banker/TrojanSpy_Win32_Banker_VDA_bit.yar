
rule TrojanSpy_Win32_Banker_VDA_bit{
	meta:
		description = "TrojanSpy:Win32/Banker.VDA!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 6f 6a 65 63 74 32 5f 58 45 35 2e 64 6c 6c 00 54 4d 65 74 68 6f 64 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 49 6e 74 65 72 63 65 70 74 } //00 00 
	condition:
		any of ($a_*)
 
}