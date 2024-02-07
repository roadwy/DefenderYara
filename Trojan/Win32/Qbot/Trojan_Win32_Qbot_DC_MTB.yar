
rule Trojan_Win32_Qbot_DC_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {6f 75 74 2e 64 6c 6c } //01 00  out.dll
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_81_2 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllUnregisterServer
		$a_81_3 = {62 65 6c 65 6d 6e 6f 69 64 65 61 } //01 00  belemnoidea
		$a_81_4 = {69 73 63 68 69 6f 61 6e 61 6c } //01 00  ischioanal
		$a_81_5 = {6f 76 65 72 68 6f 6e 65 73 74 6c 79 } //01 00  overhonestly
		$a_81_6 = {70 65 74 61 6c 6f 64 69 63 } //00 00  petalodic
	condition:
		any of ($a_*)
 
}