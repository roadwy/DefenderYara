
rule TrojanSpy_Win32_Tefosteal_C{
	meta:
		description = "TrojanSpy:Win32/Tefosteal.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 73 00 76 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}