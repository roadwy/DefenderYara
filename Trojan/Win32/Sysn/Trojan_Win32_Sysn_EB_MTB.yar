
rule Trojan_Win32_Sysn_EB_MTB{
	meta:
		description = "Trojan:Win32/Sysn.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 27 64 75 69 73 } //01 00  se'duis
		$a_01_1 = {61 76 69 6c 69 72 65 6e 74 20 64 65 27 62 6f 75 74 65 27 } //01 00  avilirent de'boute'
		$a_01_2 = {44 69 76 65 72 73 69 66 79 69 6e 67 31 } //01 00  Diversifying1
		$a_01_3 = {61 66 74 65 72 62 75 72 6e 65 72 } //01 00  afterburner
		$a_01_4 = {42 6c 61 63 6b 6c 69 73 74 69 6e 67 } //01 00  Blacklisting
		$a_01_5 = {62 6f 6f 6b 70 6c 61 74 65 73 } //01 00  bookplates
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_7 = {44 6c 6c 46 75 6e 63 74 69 6f 6e 43 61 6c 6c } //00 00  DllFunctionCall
	condition:
		any of ($a_*)
 
}