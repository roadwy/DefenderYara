
rule Trojan_Win32_Qbot_DA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_81_0 = {6f 75 74 2e 64 6c 6c } //01 00  out.dll
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_81_2 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllUnregisterServer
		$a_81_3 = {66 6f 72 65 6d 69 73 67 69 76 69 6e 67 } //01 00  foremisgiving
		$a_81_4 = {70 61 72 74 75 72 69 65 6e 63 65 } //01 00  parturience
		$a_81_5 = {70 69 6d 65 6c 69 74 69 73 } //01 00  pimelitis
		$a_81_6 = {70 6f 72 74 61 6d 65 6e 74 6f } //01 00  portamento
		$a_81_7 = {74 68 65 74 69 63 61 6c 6c 79 } //01 00  thetically
		$a_81_8 = {66 65 6c 74 6d 6f 6e 67 65 72 } //01 00  feltmonger
		$a_81_9 = {61 74 68 79 72 69 64 61 65 } //01 00  athyridae
		$a_81_10 = {6a 75 6d 61 6e 61 } //00 00  jumana
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_DA_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {5c 47 6f 6e 65 57 69 6e 74 65 72 5c 54 72 61 63 6b 53 74 61 74 65 5c 4d 61 70 68 65 61 74 5c 73 65 63 74 69 6f 6e 48 65 61 72 64 } //01 00  \GoneWinter\TrackState\Mapheat\sectionHeard
		$a_81_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_81_2 = {5f 52 65 70 65 61 74 62 72 6f 6b 65 } //01 00  _Repeatbroke
		$a_81_3 = {5f 49 6e 64 75 73 74 72 79 73 74 69 63 6b } //01 00  _Industrystick
		$a_81_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_81_5 = {47 65 74 46 69 6c 65 54 79 70 65 } //01 00  GetFileType
		$a_81_6 = {43 72 65 61 74 65 46 69 6c 65 41 } //01 00  CreateFileA
		$a_81_7 = {53 65 74 45 6e 64 4f 66 46 69 6c 65 } //01 00  SetEndOfFile
		$a_81_8 = {57 72 69 74 65 46 69 6c 65 } //01 00  WriteFile
		$a_81_9 = {6d 61 64 65 2e 64 6c 6c } //00 00  made.dll
	condition:
		any of ($a_*)
 
}