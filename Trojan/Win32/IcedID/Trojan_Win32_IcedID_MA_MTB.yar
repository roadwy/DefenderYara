
rule Trojan_Win32_IcedID_MA_MTB{
	meta:
		description = "Trojan:Win32/IcedID.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 61 69 6e 74 2e 64 6c 6c } //01 00  paint.dll
		$a_01_1 = {5c 73 69 6d 70 6c 65 5c 53 6f 6c 75 74 69 6f 6e 5c 50 6f 73 74 5c 70 61 69 6e 74 2e 70 64 62 } //01 00  \simple\Solution\Post\paint.pdb
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_3 = {54 72 79 63 6f 6d 6d 6f 6e } //01 00  Trycommon
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_5 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_6 = {4f 70 65 6e 4d 75 74 65 78 41 } //01 00  OpenMutexA
		$a_01_7 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //01 00  IsProcessorFeaturePresent
		$a_01_8 = {45 00 78 00 70 00 65 00 63 00 74 00 20 00 53 00 61 00 6d 00 65 00 57 00 72 00 69 00 74 00 65 00 20 00 54 00 65 00 61 00 63 00 68 00 } //00 00  Expect SameWrite Teach
	condition:
		any of ($a_*)
 
}