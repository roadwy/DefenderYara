
rule TrojanSpy_Win32_Banker_AAM{
	meta:
		description = "TrojanSpy:Win32/Banker.AAM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 23 78 65 72 2f 2f 3a 70 23 74 74 68 00 90 01 07 90 02 03 00 5c 76 90 05 01 01 23 65 90 05 01 01 23 72 73 90 05 01 01 23 61 6f 90 05 01 01 23 2e 64 90 05 01 01 23 6c 6c 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}