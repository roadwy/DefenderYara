
rule Backdoor_Win32_Hupigon_DE{
	meta:
		description = "Backdoor:Win32/Hupigon.DE,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 61 76 65 49 6e 2d 55 6e 70 72 65 70 61 72 65 48 65 61 64 } //01 00  WaveIn-UnprepareHead
		$a_01_1 = {5c 53 65 78 53 6f 66 74 57 } //01 00  \SexSoftW
		$a_01_2 = {4b 65 79 4c 6f 67 6f 3a } //01 00  KeyLogo:
		$a_01_3 = {47 65 74 44 72 69 76 65 72 49 } //00 00  GetDriverI
	condition:
		any of ($a_*)
 
}