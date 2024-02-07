
rule Trojan_Win32_Qbot_DD_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {6f 75 74 2e 64 6c 6c } //01 00  out.dll
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_81_2 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllUnregisterServer
		$a_81_3 = {70 79 6c 65 74 68 72 6f 6d 62 6f 70 68 6c 65 62 69 74 69 73 } //01 00  pylethrombophlebitis
		$a_81_4 = {62 61 63 74 65 72 69 63 69 64 65 } //01 00  bactericide
		$a_81_5 = {64 65 6c 69 63 61 74 65 73 73 65 } //01 00  delicatesse
		$a_81_6 = {74 6f 73 73 69 63 61 74 65 64 } //00 00  tossicated
	condition:
		any of ($a_*)
 
}