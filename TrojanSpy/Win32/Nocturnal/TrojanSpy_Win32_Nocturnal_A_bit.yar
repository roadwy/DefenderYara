
rule TrojanSpy_Win32_Nocturnal_A_bit{
	meta:
		description = "TrojanSpy:Win32/Nocturnal.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 6f 67 72 61 6d 44 61 74 61 5c 41 72 6b 65 69 } //01 00  ProgramData\Arkei
		$a_01_1 = {50 72 6f 67 72 61 6d 44 61 74 61 5c 4e 6f 63 74 75 72 6e 61 6c } //01 00  ProgramData\Nocturnal
		$a_01_2 = {5c 66 69 6c 65 73 5c 66 69 6c 65 7a 69 6c 6c 61 5f 73 69 74 65 6d 61 6e 61 67 65 72 2e 78 6d 6c } //01 00  \files\filezilla_sitemanager.xml
		$a_01_3 = {42 69 74 63 6f 69 6e 5c 77 61 6c 6c 65 74 2e 64 61 74 } //00 00  Bitcoin\wallet.dat
	condition:
		any of ($a_*)
 
}