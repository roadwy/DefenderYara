
rule Trojan_Win32_Trickbotspr_A_mod{
	meta:
		description = "Trojan:Win32/Trickbotspr.A!mod,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 6d 61 69 6e 53 70 72 65 61 64 65 72 3a 3a 69 6e 69 74 28 29 20 43 72 65 61 74 65 54 68 72 65 61 64 2c 20 65 72 72 6f 72 20 63 6f 64 65 20 25 69 } //01 00  CmainSpreader::init() CreateThread, error code %i
		$a_81_1 = {43 6d 61 69 6e 53 70 72 65 61 64 65 72 3a 3a 69 6e 69 74 28 29 20 43 72 65 61 74 65 45 76 65 6e 74 2c 20 65 72 72 6f 72 20 63 6f 64 65 20 25 69 } //01 00  CmainSpreader::init() CreateEvent, error code %i
		$a_81_2 = {57 6f 72 6d 53 68 61 72 65 } //01 00  WormShare
		$a_81_3 = {6c 73 61 73 73 2e 65 78 65 } //01 00  lsass.exe
		$a_81_4 = {45 6e 64 20 6f 66 20 52 6f 6d 61 6e 63 65 } //01 00  End of Romance
		$a_81_5 = {73 70 72 65 61 64 65 72 20 77 69 74 68 20 6d 6f 64 75 6c 65 20 68 61 6e 64 6c 65 20 30 78 25 30 38 58 20 69 73 20 73 74 61 72 74 65 64 } //00 00  spreader with module handle 0x%08X is started
	condition:
		any of ($a_*)
 
}