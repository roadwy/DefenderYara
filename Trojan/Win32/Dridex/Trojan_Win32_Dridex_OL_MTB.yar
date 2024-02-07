
rule Trojan_Win32_Dridex_OL_MTB{
	meta:
		description = "Trojan:Win32/Dridex.OL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {2d 65 73 2d 2d 70 70 2d 2d 2d 2d } //01 00  -es--pp----
		$a_81_1 = {23 50 23 45 23 45 23 54 23 50 23 2e 23 58 23 } //01 00  #P#E#E#T#P#.#X#
		$a_81_2 = {47 54 52 47 2e 70 64 62 } //01 00  GTRG.pdb
		$a_81_3 = {73 65 6c 66 2e 65 78 } //01 00  self.ex
		$a_81_4 = {41 76 69 72 61 20 47 6d 62 48 } //01 00  Avira GmbH
		$a_81_5 = {47 65 6e 65 72 61 74 65 43 6f 6e 73 6f 6c 65 43 74 72 6c 45 76 65 6e 74 } //01 00  GenerateConsoleCtrlEvent
		$a_81_6 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //00 00  OutputDebugStringA
	condition:
		any of ($a_*)
 
}